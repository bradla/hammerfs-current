/*
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 * 
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * $DragonFly: src/sys/vfs/hammer/hammer_flusher.c,v 1.45 2008/07/31 04:42:04 dillon Exp $
 */
/*
 * HAMMER dependancy flusher thread
 *
 * Meta data updates create buffer dependancies which are arranged as a
 * hierarchy of lists.
 */

#include "hammer.h"

static void hammer_flusher_master_thread(void *arg);
static void hammer_flusher_slave_thread(void *arg);
static void hammer_flusher_flush(hammer_mount_t hmp);
static void hammer_flusher_flush_inode(hammer_inode_t ip,
					hammer_transaction_t trans);

/*
 * Support structures for the flusher threads.
 */
struct hammer_flusher_info {
	TAILQ_ENTRY(hammer_flusher_info) entry;
	struct hammer_mount *hmp;
	thread_t	td;
	int		runstate;
	int		count;
	hammer_flush_group_t flg;
	hammer_inode_t	work_array[HAMMER_FLUSH_GROUP_SIZE];
};

typedef struct hammer_flusher_info *hammer_flusher_info_t;

/*
 * Sync all inodes pending on the flusher.
 *
 * All flush groups will be flushed.  This does not queue dirty inodes
 * to the flush groups, it just flushes out what has already been queued!
 */
void
hammer_flusher_sync(hammer_mount_t hmp)
{
	int seq;

	seq = hammer_flusher_async(hmp, NULL);
	hammer_flusher_wait(hmp, seq);
}

/*
 * Sync all inodes pending on the flusher - return immediately.
 *
 * All flush groups will be flushed.
 */
int
hammer_flusher_async(hammer_mount_t hmp, hammer_flush_group_t close_flg)
{
	hammer_flush_group_t flg;
	int seq = hmp->flusher.next;

	TAILQ_FOREACH(flg, &hmp->flush_group_list, flush_entry) {
		if (flg->running == 0)
			++seq;
		flg->closed = 1;
		if (flg == close_flg)
			break;
	}
	if (hmp->flusher.td) {
		if (hmp->flusher.signal++ == 0)
			wakeup(&hmp->flusher.signal);
	} else {
		seq = hmp->flusher.done;
	}
	return(seq);
}

int
hammer_flusher_async_one(hammer_mount_t hmp)
{
	int seq;

	if (hmp->flusher.td) {
		seq = hmp->flusher.next;
		if (hmp->flusher.signal++ == 0)
			wakeup(&hmp->flusher.signal);
	} else {
		seq = hmp->flusher.done;
	}
	return(seq);
}

/*
 * Wait for the flusher to get to the specified sequence number.
 * Signal the flusher as often as necessary to keep it going.
 */
void
hammer_flusher_wait(hammer_mount_t hmp, int seq)
{
	while ((int)(seq - hmp->flusher.done) > 0) {
		if (hmp->flusher.act != seq) {
			if (hmp->flusher.signal++ == 0)
				wakeup(&hmp->flusher.signal);
		}
		tsleep(&hmp->flusher.done, 0, "hmrfls", 0);
	}
}

void
hammer_flusher_wait_next(hammer_mount_t hmp)
{
	int seq;

	seq = hammer_flusher_async_one(hmp);
	hammer_flusher_wait(hmp, seq);
}

void
hammer_flusher_create(hammer_mount_t hmp)
{
	hammer_flusher_info_t info;
	int i;

	hmp->flusher.signal = 0;
	hmp->flusher.act = 0;
	hmp->flusher.done = 0;
	hmp->flusher.next = 1;
	hammer_ref(&hmp->flusher.finalize_lock);
	TAILQ_INIT(&hmp->flusher.run_list);
	TAILQ_INIT(&hmp->flusher.ready_list);

	lwkt_create(hammer_flusher_master_thread, hmp,
		    &hmp->flusher.td, NULL, 0, -1, "hammer-M");
	for (i = 0; i < HAMMER_MAX_FLUSHERS; ++i) {
		info = kmalloc(sizeof(*info), hmp->m_misc, M_WAITOK|M_ZERO);
		info->hmp = hmp;
		TAILQ_INSERT_TAIL(&hmp->flusher.ready_list, info, entry);
		lwkt_create(hammer_flusher_slave_thread, info,
			    &info->td, NULL, 0, -1, "hammer-S%d", i);
	}
}

void
hammer_flusher_destroy(hammer_mount_t hmp)
{
	hammer_flusher_info_t info;

	/*
	 * Kill the master
	 */
	hmp->flusher.exiting = 1;
	while (hmp->flusher.td) {
		++hmp->flusher.signal;
		wakeup(&hmp->flusher.signal);
		tsleep(&hmp->flusher.exiting, 0, "hmrwex", hz);
	}

	/*
	 * Kill the slaves
	 */
	while ((info = TAILQ_FIRST(&hmp->flusher.ready_list)) != NULL) {
		KKASSERT(info->runstate == 0);
		TAILQ_REMOVE(&hmp->flusher.ready_list, info, entry);
		info->runstate = -1;
		wakeup(&info->runstate);
		while (info->td)
			tsleep(&info->td, 0, "hmrwwc", 0);
		TAILQ_REMOVE(&hmp->flusher.ready_list, info, entry);
		kfree(info, hmp->m_misc);
	}
}

/*
 * The master flusher thread manages the flusher sequence id and
 * synchronization with the slave work threads.
 */
static void
hammer_flusher_master_thread(void *arg)
{
	hammer_flush_group_t flg;
	hammer_mount_t hmp;

	hmp = arg;

	for (;;) {
		/*
		 * Do at least one flush cycle.  We may have to update the
		 * UNDO FIFO even if no inodes are queued.
		 */
		for (;;) {
			while (hmp->flusher.group_lock)
				tsleep(&hmp->flusher.group_lock, 0, "hmrhld", 0);
			hmp->flusher.act = hmp->flusher.next;
			++hmp->flusher.next;
			hammer_flusher_clean_loose_ios(hmp);
			hammer_flusher_flush(hmp);
			hmp->flusher.done = hmp->flusher.act;
			wakeup(&hmp->flusher.done);
			flg = TAILQ_FIRST(&hmp->flush_group_list);
			if (flg == NULL || flg->closed == 0)
				break;
			if (hmp->flags & HAMMER_MOUNT_CRITICAL_ERROR)
				break;
		}

		/*
		 * Wait for activity.
		 */
		if (hmp->flusher.exiting && TAILQ_EMPTY(&hmp->flush_group_list))
			break;
		while (hmp->flusher.signal == 0)
			tsleep(&hmp->flusher.signal, 0, "hmrwwa", 0);

		/*
		 * Flush for each count on signal but only allow one extra
		 * flush request to build up.
		 */
		if (--hmp->flusher.signal != 0)
			hmp->flusher.signal = 1;
	}

	/*
	 * And we are done.
	 */
	hmp->flusher.td = NULL;
	wakeup(&hmp->flusher.exiting);
	lwkt_exit();
}

/*
 * Flush all inodes in the current flush group.
 */
static void
hammer_flusher_flush(hammer_mount_t hmp)
{
	hammer_flusher_info_t info;
	hammer_flush_group_t flg;
	hammer_reserve_t resv;
	hammer_inode_t ip;
	hammer_inode_t next_ip;
	int slave_index;
	int count;

	/*
	 * Just in-case there's a flush race on mount
	 */
	if (TAILQ_FIRST(&hmp->flusher.ready_list) == NULL)
		return;

	/*
	 * We only do one flg but we may have to loop/retry.
	 */
	count = 0;
	while ((flg = TAILQ_FIRST(&hmp->flush_group_list)) != NULL) {
		++count;
		if (hammer_debug_general & 0x0001) {
			kprintf("hammer_flush %d ttl=%d recs=%d\n",
				hmp->flusher.act,
				flg->total_count, flg->refs);
		}
		if (hmp->flags & HAMMER_MOUNT_CRITICAL_ERROR)
			break;
		hammer_start_transaction_fls(&hmp->flusher.trans, hmp);

		/*
		 * If the previous flush cycle just about exhausted our
		 * UNDO space we may have to do a dummy cycle to move the
		 * first_offset up before actually digging into a new cycle,
		 * or the new cycle will not have sufficient undo space.
		 */
		if (hammer_flusher_undo_exhausted(&hmp->flusher.trans, 3))
			hammer_flusher_finalize(&hmp->flusher.trans, 0);

		/*
		 * Ok, we are running this flush group now (this prevents new
		 * additions to it).
		 */
		flg->running = 1;
		if (hmp->next_flush_group == flg)
			hmp->next_flush_group = TAILQ_NEXT(flg, flush_entry);

		/*
		 * Iterate the inodes in the flg's flush_list and assign
		 * them to slaves.
		 */
		slave_index = 0;
		info = TAILQ_FIRST(&hmp->flusher.ready_list);
		next_ip = TAILQ_FIRST(&flg->flush_list);

		while ((ip = next_ip) != NULL) {
			next_ip = TAILQ_NEXT(ip, flush_entry);

			/*
			 * Add ip to the slave's work array.  The slave is
			 * not currently running.
			 */
			info->work_array[info->count++] = ip;
			if (info->count != HAMMER_FLUSH_GROUP_SIZE)
				continue;

			/*
			 * Get the slave running
			 */
			TAILQ_REMOVE(&hmp->flusher.ready_list, info, entry);
			TAILQ_INSERT_TAIL(&hmp->flusher.run_list, info, entry);
			info->flg = flg;
			info->runstate = 1;
			wakeup(&info->runstate);

			/*
			 * Get a new slave.  We may have to wait for one to
			 * finish running.
			 */
			while ((info = TAILQ_FIRST(&hmp->flusher.ready_list)) == NULL) {
				tsleep(&hmp->flusher.ready_list, 0, "hmrfcc", 0);
			}
		}

		/*
		 * Run the current slave if necessary
		 */
		if (info->count) {
			TAILQ_REMOVE(&hmp->flusher.ready_list, info, entry);
			TAILQ_INSERT_TAIL(&hmp->flusher.run_list, info, entry);
			info->flg = flg;
			info->runstate = 1;
			wakeup(&info->runstate);
		}

		/*
		 * Wait for all slaves to finish running
		 */
		while (TAILQ_FIRST(&hmp->flusher.run_list) != NULL)
			tsleep(&hmp->flusher.ready_list, 0, "hmrfcc", 0);

		/*
		 * Do the final finalization, clean up
		 */
		hammer_flusher_finalize(&hmp->flusher.trans, 1);
		hmp->flusher.tid = hmp->flusher.trans.tid;

		hammer_done_transaction(&hmp->flusher.trans);

		/*
		 * Loop up on the same flg.  If the flg is done clean it up
		 * and break out.  We only flush one flg.
		 */
		if (TAILQ_FIRST(&flg->flush_list) == NULL) {
			KKASSERT(TAILQ_EMPTY(&flg->flush_list));
			KKASSERT(flg->refs == 0);
			TAILQ_REMOVE(&hmp->flush_group_list, flg, flush_entry);
			kfree(flg, hmp->m_misc);
			break;
		}
	}

	/*
	 * We may have pure meta-data to flush, or we may have to finish
	 * cycling the UNDO FIFO, even if there were no flush groups.
	 */
	if (count == 0 && hammer_flusher_haswork(hmp)) {
		hammer_start_transaction_fls(&hmp->flusher.trans, hmp);
		hammer_flusher_finalize(&hmp->flusher.trans, 1);
		hammer_done_transaction(&hmp->flusher.trans);
	}

	/*
	 * Clean up any freed big-blocks (typically zone-2). 
	 * resv->flush_group is typically set several flush groups ahead
	 * of the free to ensure that the freed block is not reused until
	 * it can no longer be reused.
	 */
	while ((resv = TAILQ_FIRST(&hmp->delay_list)) != NULL) {
		if (resv->flush_group != hmp->flusher.act)
			break;
		hammer_reserve_clrdelay(hmp, resv);
	}
}


/*
 * The slave flusher thread pulls work off the master flush_list until no
 * work is left.
 */
static void
hammer_flusher_slave_thread(void *arg)
{
	hammer_flush_group_t flg;
	hammer_flusher_info_t info;
	hammer_mount_t hmp;
	hammer_inode_t ip;
	int i;

	info = arg;
	hmp = info->hmp;

	for (;;) {
		while (info->runstate == 0)
			tsleep(&info->runstate, 0, "hmrssw", 0);
		if (info->runstate < 0)
			break;
		flg = info->flg;

		for (i = 0; i < info->count; ++i) {
			ip = info->work_array[i];
			hammer_flusher_flush_inode(ip, &hmp->flusher.trans);
			++hammer_stats_inode_flushes;
		}
		info->count = 0;
		info->runstate = 0;
		TAILQ_REMOVE(&hmp->flusher.run_list, info, entry);
		TAILQ_INSERT_TAIL(&hmp->flusher.ready_list, info, entry);
		wakeup(&hmp->flusher.ready_list);
	}
	info->td = NULL;
	wakeup(&info->td);
	lwkt_exit();
}

void
hammer_flusher_clean_loose_ios(hammer_mount_t hmp)
{
	hammer_buffer_t buffer;
	hammer_io_t io;

	/*
	 * loose ends - buffers without bp's aren't tracked by the kernel
	 * and can build up, so clean them out.  This can occur when an
	 * IO completes on a buffer with no references left.
	 */
	if ((io = TAILQ_FIRST(&hmp->lose_list)) != NULL) {
		crit_enter();	/* biodone() race */
		while ((io = TAILQ_FIRST(&hmp->lose_list)) != NULL) {
			KKASSERT(io->mod_list == &hmp->lose_list);
			TAILQ_REMOVE(&hmp->lose_list, io, mod_entry);
			io->mod_list = NULL;
			if (io->lock.refs == 0)
				++hammer_count_refedbufs;
			hammer_ref(&io->lock);
			buffer = (void *)io;
			hammer_rel_buffer(buffer, 0);
		}
		crit_exit();
	}
}

/*
 * Flush a single inode that is part of a flush group.
 *
 * Flusher errors are extremely serious, even ENOSPC shouldn't occur because
 * the front-end should have reserved sufficient space on the media.  Any
 * error other then EWOULDBLOCK will force the mount to be read-only.
 */
static
void
hammer_flusher_flush_inode(hammer_inode_t ip, hammer_transaction_t trans)
{
	hammer_mount_t hmp = ip->hmp;
	int error;

	hammer_flusher_clean_loose_ios(hmp);
	error = hammer_sync_inode(trans, ip);

	/*
	 * EWOULDBLOCK can happen under normal operation, all other errors
	 * are considered extremely serious.  We must set WOULDBLOCK
	 * mechanics to deal with the mess left over from the abort of the
	 * previous flush.
	 */
	if (error) {
		ip->flags |= HAMMER_INODE_WOULDBLOCK;
		if (error == EWOULDBLOCK)
			error = 0;
	}
	hammer_flush_inode_done(ip, error);
	while (hmp->flusher.finalize_want)
		tsleep(&hmp->flusher.finalize_want, 0, "hmrsxx", 0);
	if (hammer_flusher_undo_exhausted(trans, 1)) {
		kprintf("HAMMER: Warning: UNDO area too small!\n");
		hammer_flusher_finalize(trans, 1);
	} else if (hammer_flusher_meta_limit(trans->hmp)) {
		hammer_flusher_finalize(trans, 0);
	}
}

/*
 * Return non-zero if the UNDO area has less then (QUARTER / 4) of its
 * space left.
 *
 * 1/4 - Emergency free undo space level.  Below this point the flusher
 *	 will finalize even if directory dependancies have not been resolved.
 *
 * 2/4 - Used by the pruning and reblocking code.  These functions may be
 *	 running in parallel with a flush and cannot be allowed to drop
 *	 available undo space to emergency levels.
 *
 * 3/4 - Used at the beginning of a flush to force-sync the volume header
 *	 to give the flush plenty of runway to work in.
 */
int
hammer_flusher_undo_exhausted(hammer_transaction_t trans, int quarter)
{
	if (hammer_undo_space(trans) <
	    hammer_undo_max(trans->hmp) * quarter / 4) {
		return(1);
	} else {
		return(0);
	}
}

/*
 * Flush all pending UNDOs, wait for write completion, update the volume
 * header with the new UNDO end position, and flush it.  Then
 * asynchronously flush the meta-data.
 *
 * If this is the last finalization in a flush group we also synchronize
 * our cached blockmap and set hmp->flusher_undo_start and our cached undo
 * fifo first_offset so the next flush resets the FIFO pointers.
 *
 * If this is not final it is being called because too many dirty meta-data
 * buffers have built up and must be flushed with UNDO synchronization to
 * avoid a buffer cache deadlock.
 */
void
hammer_flusher_finalize(hammer_transaction_t trans, int final)
{
	hammer_volume_t root_volume;
	hammer_blockmap_t cundomap, dundomap;
	hammer_mount_t hmp;
	hammer_io_t io;
	int count;
	int i;

	hmp = trans->hmp;
	root_volume = trans->rootvol;

	/*
	 * Exclusively lock the flusher.  This guarantees that all dirty
	 * buffers will be idled (have a mod-count of 0).
	 */
	++hmp->flusher.finalize_want;
	hammer_lock_ex(&hmp->flusher.finalize_lock);

	/*
	 * If this isn't the final sync several threads may have hit the
	 * meta-limit at the same time and raced.  Only sync if we really
	 * have to, after acquiring the lock.
	 */
	if (final == 0 && !hammer_flusher_meta_limit(hmp))
		goto done;

	if (hmp->flags & HAMMER_MOUNT_CRITICAL_ERROR)
		goto done;

	/*
	 * Flush data buffers.  This can occur asynchronously and at any
	 * time.  We must interlock against the frontend direct-data write
	 * but do not have to acquire the sync-lock yet.
	 */
	count = 0;
	while ((io = TAILQ_FIRST(&hmp->data_list)) != NULL) {
		if (io->ioerror)
			break;
		if (io->lock.refs == 0)
			++hammer_count_refedbufs;
		hammer_ref(&io->lock);
		hammer_io_write_interlock(io);
		KKASSERT(io->type != HAMMER_STRUCTURE_VOLUME);
		hammer_io_flush(io);
		hammer_io_done_interlock(io);
		hammer_rel_buffer((hammer_buffer_t)io, 0);
		++count;
	}

	/*
	 * The sync-lock is required for the remaining sequence.  This lock
	 * prevents meta-data from being modified.
	 */
	hammer_sync_lock_ex(trans);

	/*
	 * If we have been asked to finalize the volume header sync the
	 * cached blockmap to the on-disk blockmap.  Generate an UNDO
	 * record for the update.
	 */
	if (final) {
		cundomap = &hmp->blockmap[0];
		dundomap = &root_volume->ondisk->vol0_blockmap[0];
		if (root_volume->io.modified) {
			hammer_modify_volume(trans, root_volume,
					     dundomap, sizeof(hmp->blockmap));
			for (i = 0; i < HAMMER_MAX_ZONES; ++i)
				hammer_crc_set_blockmap(&cundomap[i]);
			bcopy(cundomap, dundomap, sizeof(hmp->blockmap));
			hammer_modify_volume_done(root_volume);
		}
	}

	/*
	 * Flush UNDOs
	 */
	count = 0;
	while ((io = TAILQ_FIRST(&hmp->undo_list)) != NULL) {
		if (io->ioerror)
			break;
		KKASSERT(io->modify_refs == 0);
		if (io->lock.refs == 0)
			++hammer_count_refedbufs;
		hammer_ref(&io->lock);
		KKASSERT(io->type != HAMMER_STRUCTURE_VOLUME);
		hammer_io_flush(io);
		hammer_rel_buffer((hammer_buffer_t)io, 0);
		++count;
	}

	/*
	 * Wait for I/Os to complete
	 */
	hammer_flusher_clean_loose_ios(hmp);
	hammer_io_wait_all(hmp, "hmrfl1");

	if (hmp->flags & HAMMER_MOUNT_CRITICAL_ERROR)
		goto failed;

	/*
	 * Update the on-disk volume header with new UNDO FIFO end position
	 * (do not generate new UNDO records for this change).  We have to
	 * do this for the UNDO FIFO whether (final) is set or not.
	 *
	 * Also update the on-disk next_tid field.  This does not require
	 * an UNDO.  However, because our TID is generated before we get
	 * the sync lock another sync may have beat us to the punch.
	 *
	 * This also has the side effect of updating first_offset based on
	 * a prior finalization when the first finalization of the next flush
	 * cycle occurs, removing any undo info from the prior finalization
	 * from consideration.
	 *
	 * The volume header will be flushed out synchronously.
	 */
	dundomap = &root_volume->ondisk->vol0_blockmap[HAMMER_ZONE_UNDO_INDEX];
	cundomap = &hmp->blockmap[HAMMER_ZONE_UNDO_INDEX];

	if (dundomap->first_offset != cundomap->first_offset ||
		   dundomap->next_offset != cundomap->next_offset) {
		hammer_modify_volume(NULL, root_volume, NULL, 0);
		dundomap->first_offset = cundomap->first_offset;
		dundomap->next_offset = cundomap->next_offset;
		hammer_crc_set_blockmap(dundomap);
		hammer_modify_volume_done(root_volume);
	}

	/*
	 * vol0_next_tid is used for TID selection and is updated without
	 * an UNDO so we do not reuse a TID that may have been rolled-back.
	 *
	 * vol0_last_tid is the highest fully-synchronized TID.  It is
	 * set-up when the UNDO fifo is fully synced, later on (not here).
	 */
	if (root_volume->io.modified) {
		hammer_modify_volume(NULL, root_volume, NULL, 0);
		if (root_volume->ondisk->vol0_next_tid < trans->tid)
			root_volume->ondisk->vol0_next_tid = trans->tid;
		hammer_crc_set_volume(root_volume->ondisk);
		hammer_modify_volume_done(root_volume);
		hammer_io_flush(&root_volume->io);
	}

	/*
	 * Wait for I/Os to complete
	 */
	hammer_flusher_clean_loose_ios(hmp);
	hammer_io_wait_all(hmp, "hmrfl2");

	if (hmp->flags & HAMMER_MOUNT_CRITICAL_ERROR)
		goto failed;

	/*
	 * Flush meta-data.  The meta-data will be undone if we crash
	 * so we can safely flush it asynchronously.
	 *
	 * Repeated catchups will wind up flushing this update's meta-data
	 * and the UNDO buffers for the next update simultaniously.  This
	 * is ok.
	 */
	count = 0;
	while ((io = TAILQ_FIRST(&hmp->meta_list)) != NULL) {
		if (io->ioerror)
			break;
		KKASSERT(io->modify_refs == 0);
		if (io->lock.refs == 0)
			++hammer_count_refedbufs;
		hammer_ref(&io->lock);
		KKASSERT(io->type != HAMMER_STRUCTURE_VOLUME);
		hammer_io_flush(io);
		hammer_rel_buffer((hammer_buffer_t)io, 0);
		++count;
	}

	/*
	 * If this is the final finalization for the flush group set
	 * up for the next sequence by setting a new first_offset in
	 * our cached blockmap and clearing the undo history.
	 *
	 * Even though we have updated our cached first_offset, the on-disk
	 * first_offset still governs available-undo-space calculations.
	 */
	if (final) {
		cundomap = &hmp->blockmap[HAMMER_ZONE_UNDO_INDEX];
		if (cundomap->first_offset == cundomap->next_offset) {
			hmp->hflags &= ~HMNT_UNDO_DIRTY;
		} else {
			cundomap->first_offset = cundomap->next_offset;
			hmp->hflags |= HMNT_UNDO_DIRTY;
		}
		hammer_clear_undo_history(hmp);

		/*
		 * Flush tid sequencing.  flush_tid1 is fully synchronized,
		 * meaning a crash will not roll it back.  flush_tid2 has
		 * been written out asynchronously and a crash will roll
		 * it back.  flush_tid1 is used for all mirroring masters.
		 */
		if (hmp->flush_tid1 != hmp->flush_tid2) {
			hmp->flush_tid1 = hmp->flush_tid2;
			wakeup(&hmp->flush_tid1);
		}
		hmp->flush_tid2 = trans->tid;
	}

	/*
	 * Cleanup.  Report any critical errors.
	 */
failed:
	hammer_sync_unlock(trans);

	if (hmp->flags & HAMMER_MOUNT_CRITICAL_ERROR) {
		kprintf("HAMMER(%s): Critical write error during flush, "
			"refusing to sync UNDO FIFO\n",
			root_volume->ondisk->vol_name);
	}

done:
	hammer_unlock(&hmp->flusher.finalize_lock);

	if (--hmp->flusher.finalize_want == 0)
		wakeup(&hmp->flusher.finalize_want);
	hammer_stats_commits += final;
}

/*
 * Return non-zero if too many dirty meta-data buffers have built up.
 *
 * Since we cannot allow such buffers to flush until we have dealt with
 * the UNDOs, we risk deadlocking the kernel's buffer cache.
 */
int
hammer_flusher_meta_limit(hammer_mount_t hmp)
{
	if (hmp->locked_dirty_space + hmp->io_running_space >
	    hammer_limit_dirtybufspace) {
		return(1);
	}
	return(0);
}

/*
 * Return non-zero if too many dirty meta-data buffers have built up.
 *
 * This version is used by background operations (mirror, prune, reblock)
 * to leave room for foreground operations.
 */
int
hammer_flusher_meta_halflimit(hammer_mount_t hmp)
{
	if (hmp->locked_dirty_space + hmp->io_running_space >
	    hammer_limit_dirtybufspace / 2) {
		return(1);
	}
	return(0);
}

/*
 * Return non-zero if the flusher still has something to flush.
 */
int
hammer_flusher_haswork(hammer_mount_t hmp)
{
	if (hmp->flags & HAMMER_MOUNT_CRITICAL_ERROR)
		return(0);
	if (TAILQ_FIRST(&hmp->flush_group_list) ||	/* dirty inodes */
	    TAILQ_FIRST(&hmp->volu_list) ||		/* dirty bufffers */
	    TAILQ_FIRST(&hmp->undo_list) ||
	    TAILQ_FIRST(&hmp->data_list) ||
	    TAILQ_FIRST(&hmp->meta_list) ||
	    (hmp->hflags & HMNT_UNDO_DIRTY)		/* UNDO FIFO sync */
	) {
		return(1);
	}
	return(0);
}

