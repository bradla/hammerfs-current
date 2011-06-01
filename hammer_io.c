/*
 * Copyright (c) 2007-2008 The DragonFly Project.  All rights reserved.
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
 * $DragonFly: src/sys/vfs/hammer/hammer_io.c,v 1.55 2008/09/15 17:02:49 dillon Exp $
 */
/*
 * IO Primitives and buffer cache management
 *
 * All major data-tracking structures in HAMMER contain a struct hammer_io
 * which is used to manage their backing store.  We use filesystem buffers
 * for backing store and we leave them passively associated with their
 * HAMMER structures.
 *
 * If the kernel tries to destroy a passively associated buf which we cannot
 * yet let go we set B_LOCKED in the buffer and then actively released it
 * later when we can.
 *
 * The io_token is required for anything which might race bioops and bio_done
 * callbacks, with one exception: A successful hammer_try_interlock_norefs().
 * the fs_token will be held in all other cases.
 */

#include <linux/buffer_head.h> // for sb_bread

#include "dfly_wrap.h"

#include "hammer.h"
#include "dfly/sys/fcntl.h"
#include "dfly/sys/nlookup.h"
#include "dfly/sys/buf.h"
#include "dfly/sys/buf2.h"

int hammer_limit_running_io;
   
/*
 * These are currently used only by the soft dependency code, hence
 * are stored once in a global variable. If other subsystems wanted
 * to use these hooks, a pointer to a set of bio_ops could be added
 * to each buffer.
 */
struct bio_ops {
         TAILQ_ENTRY(bio_ops) entry;
         void    (*io_start) (struct buf *);
         void    (*io_complete) (struct buffer_head *);
         void    (*io_direct_read_complete) (struct bio *);
         void    (*io_deallocate) (struct buffer_head *);
         int     (*io_fsync) (struct vnode *);
         int     (*io_sync) (struct mount *);
         void    (*io_movedeps) (struct buf *, struct buf *);
         int     (*io_countdeps) (struct buf *, int);
         int     (*io_checkread) (struct buf *);
         int     (*io_checkwrite) (struct buf *);
};

static void hammer_io_modify(hammer_io_t io, int count);
static void hammer_io_deallocate(struct buffer_head *bp);

static void hammer_io_direct_read_complete(struct bio *nbio);

/* 
static void hammer_io_direct_write_complete(struct bio_vec *nbio);
*/
static int hammer_io_direct_uncache_callback(hammer_inode_t ip, void *data);
static void hammer_io_set_modlist(struct hammer_io *io);
static void hammer_io_flush_mark(hammer_volume_t volume);
/* static void hammer_io_flush_sync_done(struct bio *bio); */

/*
 * Initialize a new, already-zero'd hammer_io structure, or reinitialize
 * an existing hammer_io structure which may have switched to another type.
 */
void
hammer_io_init(hammer_io_t io, hammer_volume_t volume, enum hammer_io_type type)
{
	io->volume = volume;
	io->hmp = volume->io.hmp;
	io->type = type;
}

/*
 * Helper routine to disassociate a buffer cache buffer from an I/O
 * structure.  The io must be interlocked and marked appropriately for
 * reclamation.
 *
 * The io must be in a released state with the io->bp owned and
 * locked by the caller of this function.  When not called from an
 * io_deallocate() this cannot race an io_deallocate() since the
 * kernel would be unable to get the buffer lock in that case.
 * (The released state in this case means we own the bp, not the
 * hammer_io structure).
 *
 * The io may have 0 or 1 references depending on who called us.  The
 * caller is responsible for dealing with the refs.
 *
 * This call can only be made when no action is required on the buffer.
 *
 * This function is guaranteed not to race against anything because we
 * own both the io lock and the bp lock and are interlocked with no
 * references.
 */

static void
hammer_io_disassociate(hammer_io_structure_t iou)
{
  /*   panic("hammer_io_disassociate"); */

	struct buf *bp = iou->io.bp;

	KKASSERT(iou->io.released);
	KKASSERT(iou->io.modified == 0);
	/* XXX KKASSERT(LIST_FIRST(&bp->b_dep) == (void *)iou);
	buf_dep_init(bp); */
	iou->io.bp = NULL;

	/*
	 * If the buffer was locked someone wanted to get rid of it.
	 */
	if (bp->b_flags & B_LOCKED) {
		--hammer_count_io_locked;
		bp->b_flags &= ~B_LOCKED;
	}
	if (iou->io.reclaim) {
		bp->b_flags |= B_NOCACHE|B_RELBUF;
		iou->io.reclaim = 0;
	}

	switch(iou->io.type) {
	case HAMMER_STRUCTURE_VOLUME:
		iou->volume.ondisk = NULL;
		break;
	case HAMMER_STRUCTURE_DATA_BUFFER:
	case HAMMER_STRUCTURE_META_BUFFER:
	case HAMMER_STRUCTURE_UNDO_BUFFER:
		iou->buffer.ondisk = NULL;
		break;
	case HAMMER_STRUCTURE_DUMMY:
		panic("hammer_io_disassociate: bad io type");
		break;

	}
}

/*
 * Wait for any physical IO to complete
 *
 * XXX we aren't interlocked against a spinlock or anything so there
 *     is a small window in the interlock / io->running == 0 test.
 */
void
hammer_io_wait(hammer_io_t io)
{
/*    panic("hammer_io_wait"); */

	if (io->running) {
		crit_enter();
		/* XXX tsleep_interlock(io); */
		io->waiting = 1;
		for (;;) {
			tsleep(io, 0, "hmrflw", 0);
			if (io->running == 0)
				break;
			/* tsleep_interlock(io); */
			io->waiting = 1;
			if (io->running == 0)
				break;
		}
		crit_exit();
	}
}

/*
 * Wait for all currently queued HAMMER-initiated I/Os to complete.
 *
 * This is not supposed to count direct I/O's but some can leak
 * through (for non-full-sized direct I/Os).
 */

void
hammer_io_wait_all(hammer_mount_t hmp, const char *ident, int doflush)
{
 /*   panic("hammer_io_wait_all"); */
	struct hammer_io iodummy;
	hammer_io_t io;

	/*
	 * Degenerate case, no I/O is running
	 */
	crit_enter();
	if (TAILQ_EMPTY(&hmp->iorun_list)) {
		crit_exit();
		if (doflush)
			hammer_io_flush_sync(hmp);
		return;
	}
	bzero(&iodummy, sizeof(iodummy));
	iodummy.type = HAMMER_STRUCTURE_DUMMY;

	/*
	 * Add placemarker and then wait until it becomes the head of
	 * the list.
	 */
	TAILQ_INSERT_TAIL(&hmp->iorun_list, &iodummy, iorun_entry);
	while (TAILQ_FIRST(&hmp->iorun_list) != &iodummy) {
		tsleep(&iodummy, 0, ident, 0);
	}

	/*
	 * Chain in case several placemarkers are present.
	 */
	TAILQ_REMOVE(&hmp->iorun_list, &iodummy, iorun_entry);
	io = TAILQ_FIRST(&hmp->iorun_list);
	if (io && io->type == HAMMER_STRUCTURE_DUMMY)
		wakeup(io);
	crit_exit();

	if (doflush)

	hammer_io_flush_sync(hmp);
/*	
	crit_enter();
	while (hmp->io_running_space)
		tsleep(&hmp->io_running_space, 0, ident, 0);
	crit_exit();
*/
}

#define HAMMER_MAXRA	4

/*
 * Clear a flagged error condition on a I/O buffer.  The caller must hold
 * its own ref on the buffer.
 */
void
hammer_io_clear_error(struct hammer_io *io)
{
	/* hammer_mount_t hmp = io->hmp; */

	crit_enter();
	if (io->ioerror) {
		io->ioerror = 0;
		hammer_rel(&io->lock);
		KKASSERT(hammer_isactive(&io->lock));
	}
	crit_exit();
}

void
hammer_io_clear_error_noassert(struct hammer_io *io)
{
/*	hammer_mount_t hmp = io->hmp; */

	crit_enter();
	if (io->ioerror) {
		io->ioerror = 0;
		hammer_rel(&io->lock);
	}
	crit_exit();
}

/*
 * This is an advisory function only which tells the buffer cache
 * the bp is not a meta-data buffer, even though it is backed by
 * a block device.
 *
 * This is used by HAMMER's reblocking code to avoid trying to
 * swapcache the filesystem's data when it is read or written
 * by the reblocking code.
 *
 * The caller has a ref on the buffer preventing the bp from
 * being disassociated from it.
 */
void
hammer_io_notmeta(hammer_buffer_t buffer)
{
	if ((buffer->io.bp->b_flags & B_NOTMETA) == 0) {
		/* hammer_mount_t hmp = buffer->io.hmp; */

		crit_enter();
		buffer->io.bp->b_flags |= B_NOTMETA;
		crit_exit();
	}
}



/*
 * Load bp for a HAMMER structure.  The io must be exclusively locked by
 * the caller.
 *
 * This routine is mostly used on meta-data and small-data blocks.  Generally
 * speaking HAMMER assumes some locality of reference and will cluster.
 *
 * Note that the caller (hammer_ondisk.c) may place further restrictions
 * on clusterability via the limit (in bytes).  Typically large-data
 * zones cannot be clustered due to their mixed buffer sizes.  This is
 * not an issue since such clustering occurs in hammer_vnops at the
 * regular file layer, whereas this is the buffered block device layer.
 *
 * No I/O callbacks can occur while we hold the buffer locked.
 */
int
hammer_io_read(struct super_block *sb, struct hammer_io *io, int limit)
{
	struct buf *bp;
        int   error=0;
        /* char *metatype; */
        
	if ((bp = io->bp) == NULL) {
	        ++hammer_count_io_locked;
		/* atomic_add_int(&hammer_count_io_running_read, io->bytes); */
		
		if (hammer_cluster_enable && limit > io->bytes) {
			/* error = cluster_read(devvp, io->offset + limit,
					     io->offset, io->bytes,
					     HAMMER_CLUSTER_SIZE,
					     HAMMER_CLUSTER_SIZE,
					     &io->bp); */
			kprintf("cluser_read\n");
		} else {
			error = bread(sb, io->offset, io->bytes, &io->bp);
		}
		hammer_stats_disk_read += io->bytes;
		++hammer_count_io_locked;
		/* atomic_add_int(&hammer_count_io_running_read, -io->bytes); */

		/*
		 * The code generally assumes b_ops/b_dep has been set-up,
		 * even if we error out here.
		 */
		bp = io->bp;
		if ((hammer_debug_io & 0x0001) && (bp->b_flags & B_IODEBUG)) {
			switch(io->type) {
			case HAMMER_STRUCTURE_VOLUME:
				/* metatype = "volume"; XXX fix */
				break;
			case HAMMER_STRUCTURE_META_BUFFER:
				switch(((struct hammer_buffer *)io)->
					zoneX_offset & HAMMER_OFF_ZONE_MASK) {
				case HAMMER_ZONE_BTREE:
					/* metatype = "btree"; */
					break;
				case HAMMER_ZONE_META:
					/* metatype = "meta"; */
					break;
				case HAMMER_ZONE_FREEMAP:
					/* metatype = "freemap"; */
					break;
				default:
					/* metatype = "meta?"; */
					break;
				}
				break;
			case HAMMER_STRUCTURE_DATA_BUFFER:
				/* metatype = "data"; */
				break;
			case HAMMER_STRUCTURE_UNDO_BUFFER:
				/* metatype = "undo"; */
				break;
			default:
				/* metatype = "unknown"; */
				break;
			}
/* XXX			kprintf("doff %016jx %s\n",
				(unsigned long)bp->b_bio2.bio_offset,
				metatype); */
		}
		bp->b_flags &= ~B_IODEBUG;
		/* XXX bp->b_ops = &hammer_bioops;
		KKASSERT(LIST_FIRST(&bp->b_dep) == NULL); */

		/* io->worklist is locked by the io lock */
		/* LIST_INSERT_HEAD(&bp->b_dep, &io->worklist, node); */
		/* XXX BUF_KERNPROC(bp); */
		KKASSERT(io->modified == 0);
		KKASSERT(io->running == 0);
		KKASSERT(io->waiting == 0);
		io->released = 0;	/* we hold an active lock on bp */
	} else {
		error = 0;
	}
	return(error);
}

/* Similar to hammer_io_read() but returns a zero'd out buffer instead.
 *
 * Must be called with the IO exclusively locked.
 *
 * vfs_bio_clrbuf() is kinda nasty, enforce serialization against background
 * I/O by forcing the buffer to not be in a released state before calling
 * it.
 *
 * This function will also mark the IO as modified but it will not
 * increment the modify_refs count.
 *
 * No I/O callbacks can occur while we hold the buffer locked.
 */
int
hammer_io_new(struct super_block *sb, struct hammer_io *io)
{
#if 0
  /*  panic("hammer_io_new"); */
	struct buf *bp;

	if ((bp = io->bp) == NULL) {
/*		io->bp = sb_getblk(sb, io->offset, io->bytes, 0); */
		io->bp = sb_getblk(sb, io->bytes);
		bp = io->bp;
		/* bp->b_ops = &hammer_bioops;
		KKASSERT(LIST_FIRST(&bp->b_dep) == NULL); */
		
		/* io->worklist is locked by the io lock */
		/* LIST_INSERT_HEAD(&bp->b_dep, &io->worklist, node); */
		io->released = 0;
		KKASSERT(io->running == 0);
		io->waiting = 0;
		/* XXX BUF_KERNPROC(bp); */
	} else {
		if (io->released) {
			/* XXX regetblk(bp); 
			BUF_KERNPROC(bp); */
			io->released = 0;
		}
	}
	hammer_io_modify(io, 0);
	/* XXX vfs_bio_clrbuf(bp); */
#endif
        printk("hammer_io_new");
	return(0);
}

/*
 * Advance the activity count on the underlying buffer because
 * HAMMER does not getblk/brelse on every access.
 *
 * The io->bp cannot go away while the buffer is referenced.
 */
void
hammer_io_advance(struct hammer_io *io)
{
/*	if (io->bp) */
		/* XXX buf_act_advance(io->bp); */
}

/*
 * Remove potential device level aliases against buffers managed by high level
 * vnodes.  Aliases can also be created due to mixed buffer sizes or via
 * direct access to the backing store device.
 *
 * This is nasty because the buffers are also VMIO-backed.  Even if a buffer
 * does not exist its backing VM pages might, and we have to invalidate
 * those as well or a getblk() will reinstate them.
 *
 * Buffer cache buffers associated with hammer_buffers cannot be
 * invalidated.
 */
int
hammer_io_inval(hammer_volume_t volume, hammer_off_t zone2_offset)
{
        int error=0;
#if 0

	// XXX hammer_io_structure_t iou;
	hammer_mount_t hmp;
	hammer_off_t phys_offset;
	/* struct buf *bp; */
	struct buffer_head *bp;
	

	hmp = volume->io.hmp;
	
	/*
	 * Warning: FINDBLK_TEST return stable storage but not stable
	 *	    contents.  It happens to be ok in this case.
	 */

	phys_offset = volume->ondisk->vol_buf_beg +
		      (zone2_offset & HAMMER_OFF_SHORT_MASK);
	crit_enter();
	/* if ((bp = findblk(volume->devvp, phys_offset)) != NULL) */
		bp = sb_getblk(volume->sb, bp->b_size);
	/*
	else 
		bp = getblk(volume->devvp, phys_offset, HAMMER_BUFSIZE, 0, 0); */
/*	if ((iou = (void *)LIST_FIRST(&bp->b_dep)) != NULL) { XXX */
#if 0
		hammer_ref(&iou->io.lock);
		hammer_io_clear_modify(&iou->io, 1);
		bundirty(bp);
		iou->io.released = 0;
		BUF_KERNPROC(bp);
		iou->io.reclaim = 1;
		iou->io.waitdep = 1;
		KKASSERT(iou->io.lock.refs == 1);
		hammer_rel_buffer(&iou->buffer, 0);
		/*hammer_io_deallocate(bp);*/
#endif
		/* XXX bqrelse(bp); */
		error = EAGAIN;
/*	} else { */
		KKASSERT((bp->b_state & B_LOCKED) == 0);
		/* bundirty(bp); */
		bp->b_state |= B_NOCACHE|B_RELBUF;
		/* brelse(bp); */
		error = 0;
	crit_exit();
#endif
        printk("hammer_io_inval");
        return(error);
}

/*
 * This routine is called on the last reference to a hammer structure.
 * The io is usually interlocked with io.loading and io.refs must be 1.
 *
 * This routine may return a non-NULL bp to the caller for dispoal.  Disposal
 * simply means the caller finishes decrementing the ref-count on the 
 * IO structure then brelse()'s the bp.  The bp may or may not still be
 * passively associated with the IO.
 * 
 * The only requirement here is that modified meta-data and volume-header
 * buffer may NOT be disassociated from the IO structure, and consequently
 * we also leave such buffers actively associated with the IO if they already
 * are (since the kernel can't do anything with them anyway).  Only the
 * flusher is allowed to write such buffers out.  Modified pure-data and
 * undo buffers are returned to the kernel but left passively associated
 * so we can track when the kernel writes the bp out.
 */
struct buf *
hammer_io_release(struct hammer_io *io, int flush)
{
    /* panic("hammer_io_release"); */

	union hammer_io_structure *iou = (void *)io;
	struct buf *bp;

	if ((bp = io->bp) == NULL)
		return(NULL);

	/*
	 * Try to flush a dirty IO to disk if asked to by the
	 * caller or if the kernel tried to flush the buffer in the past.
	 *
	 * Kernel-initiated flushes are only allowed for pure-data buffers.
	 * meta-data and volume buffers can only be flushed explicitly
	 * by HAMMER.
	 */
	if (io->modified) {
		if (flush) {
			hammer_io_flush(io, 0);
		} else if (bp->b_flags & B_LOCKED) {
			switch(io->type) {
			case HAMMER_STRUCTURE_DATA_BUFFER:
				hammer_io_flush(io, 0);
				break;
			case HAMMER_STRUCTURE_UNDO_BUFFER:
				hammer_io_flush(io, hammer_undo_reclaim(io));
				break;
			default:
				break;
			}
		} /* else no explicit request to flush the buffer */
	}

	/*
	 * Wait for the IO to complete if asked to.  This occurs when
	 * the buffer must be disposed of definitively during an umount
	 * or buffer invalidation.
	 */
	if (io->waitdep && io->running) {
		hammer_io_wait(io);
	}

	/*
	 * Return control of the buffer to the kernel (with the provisio
	 * that our bioops can override kernel decisions with regards to
	 * the buffer).
	 */
	if ((flush || io->reclaim) && io->modified == 0 && io->running == 0) {
		/*
		 * Always disassociate the bp if an explicit flush
		 * was requested and the IO completed with no error
		 * (so unmount can really clean up the structure).
		 */
		if (io->released) {
		        printk("io->released\n");
		/* XXX	regetblk(bp);
			BUF_KERNPROC(bp); */
		} else {
			io->released = 1;
		}
		hammer_io_disassociate((hammer_io_structure_t)io);
		/* return the bp */
	} else if (io->modified) {
		/*
		 * Only certain IO types can be released to the kernel if
		 * the buffer has been modified.
		 *
		 * volume and meta-data IO types may only be explicitly
		 * flushed by HAMMER.
		 */
		switch(io->type) {
		case HAMMER_STRUCTURE_DATA_BUFFER:
		case HAMMER_STRUCTURE_UNDO_BUFFER:
			if (io->released == 0) {
				io->released = 1;
				/* XXX bdwrite(bp); */
			}
			break;
		default:
			break;
		}
		bp = NULL;	/* bp left associated */
	} else if (io->released == 0) {
		/*
		 * Clean buffers can be generally released to the kernel.
		 * We leave the bp passively associated with the HAMMER
		 * structure and use bioops to disconnect it later on
		 * if the kernel wants to discard the buffer.
		 *
		 * We can steal the structure's ownership of the bp.
		 */
		io->released = 1;
		if (bp->b_flags & B_LOCKED) {
			hammer_io_disassociate(iou);
			/* return the bp */
		} else {
			if (io->reclaim) {
				hammer_io_disassociate(iou);
				/* return the bp */
			} else {
				/* return the bp (bp passively associated) */
			}
		}
	} else {
		/*
		 * A released buffer is passively associate with our
		 * hammer_io structure.  The kernel cannot destroy it
		 * without making a bioops call.  If the kernel (B_LOCKED)
		 * or we (reclaim) requested that the buffer be destroyed
		 * we destroy it, otherwise we do a quick get/release to
		 * reset its position in the kernel's LRU list.
		 *
		 * Leaving the buffer passively associated allows us to
		 * use the kernel's LRU buffer flushing mechanisms rather
		 * then rolling our own.
		 *
		 * XXX there are two ways of doing this.  We can re-acquire
		 * and passively release to reset the LRU, or not.
		 */
		if (io->running == 0) {
			/* regetblk(bp); */
			if ((bp->b_flags & B_LOCKED) || io->reclaim) {
				hammer_io_disassociate(iou);
				/* return the bp */
			} else {
				/* return the bp (bp passively associated) */
			}
		} else {
			/*
			 * bp is left passively associated but we do not
			 * try to reacquire it.  Interactions with the io
			 * structure will occur on completion of the bp's
			 * I/O.
			 */
			bp = NULL;
		}
	}
	return(bp);
}

/*
 * This routine is called with a locked IO when a flush is desired and
 * no other references to the structure exists other then ours.  This
 * routine is ONLY called when HAMMER believes it is safe to flush a
 * potentially modified buffer out.
 *
 * The locked io or io reference prevents a flush from being initiated
 * by the kernel.
 */
void
hammer_io_flush(struct hammer_io *io, int reclaim)
{
   /* panic("hammer_io_flush"); */

	struct buf *bp;
	hammer_mount_t hmp;

	/*
	 * Degenerate case - nothing to flush if nothing is dirty.
	 */
	if (io->modified == 0) {
		return;
	}

	KKASSERT(io->bp);
	KKASSERT(io->modify_refs <= 0);

	/*
	 * Acquire ownership of the bp, particularly before we clear our
	 * modified flag.
	 *
	 * We are going to bawrite() this bp.  Don't leave a window where
	 * io->released is set, we actually own the bp rather then our
	 * buffer.
	 *
	 * The io_token should not be required here as only
	 */
	hmp = io->hmp;
	bp = io->bp;
	if (io->released) {
		/* regetblk(bp);
		 BUF_KERNPROC(io->bp); */
		/* io->released = 0; */
		KKASSERT(io->released);
		KKASSERT(io->bp == bp);
	} else {
		io->released = 1;
	}

	if (reclaim) {
		io->reclaim = 1;
		if ((bp->b_flags & B_LOCKED) == 0) {
			bp->b_flags |= B_LOCKED;
			++hammer_count_io_locked;
			/* atomic_add_int(&hammer_count_io_locked, 1); */
		}
	}
	io->released = 1;

	/*
	 * Acquire exclusive access to the bp and then clear the modified
	 * state of the buffer prior to issuing I/O to interlock any
	 * modifications made while the I/O is in progress.  This shouldn't
	 * happen anyway but losing data would be worse.  The modified bit
	 * will be rechecked after the IO completes.
	 *
	 * NOTE: This call also finalizes the buffer's content (inval == 0).
	 *
	 * This is only legal when lock.refs == 1 (otherwise we might clear
	 * the modified bit while there are still users of the cluster
	 * modifying the data).
	 *
	 * Do this before potentially blocking so any attempt to modify the
	 * ondisk while we are blocked blocks waiting for us.
	 */
	hammer_ref(&io->lock);
	hammer_io_clear_modify(io, 0);
	hammer_rel(&io->lock);
	/* hammer_unref(&io->lock); */

	if (hammer_debug_io & 0x0002)
		kprintf("hammer io_write \n"); /* , bp->b_bio1.bio_offset); */

	/*
	 * Transfer ownership to the kernel and initiate I/O.
	 *
	 * NOTE: We do not hold io_token so an atomic op is required to
	 *	 update io_running_space.
	 */
	io->running = 1;
	io->hmp->io_running_space += io->bytes;
	hammer_count_io_running_write += io->bytes;
	/* XXX atomic_add_int(&hmp->io_running_space, io->bytes);
	atomic_add_int(&hammer_count_io_running_write, io->bytes);
         */
        ++hammer_count_io_locked;
        crit_enter();
	TAILQ_INSERT_TAIL(&hmp->iorun_list, io, iorun_entry);
	crit_exit();
	/* XXX bawrite(bp); */
	hammer_io_flush_mark(io->volume);
}

/************************************************************************
 *				BUFFER DIRTYING				*
 ************************************************************************
 *
 * These routines deal with dependancies created when IO buffers get
 * modified.  The caller must call hammer_modify_*() on a referenced
 * HAMMER structure prior to modifying its on-disk data.
 *
 * Any intent to modify an IO buffer acquires the related bp and imposes
 * various write ordering dependancies.
 */

/*
 * Mark a HAMMER structure as undergoing modification.  Meta-data buffers
 * are locked until the flusher can deal with them, pure data buffers
 * can be written out.
 *
 * The referenced io prevents races.
 */
static
void
hammer_io_modify(hammer_io_t io, int count)
{
   /* panic("hammer_io_modify"); */

	/*
	 * io->modify_refs must be >= 0
	 */
	while (io->modify_refs < 0) {
		io->waitmod = 1;
		tsleep(io, 0, "hmrmod", 0);
	}

	/*
	 * Shortcut if nothing to do.
	 */
	KKASSERT(io->lock.refs != 0 && io->bp != NULL);
	io->modify_refs += count;
	if (io->modified && io->released == 0)
		return;

        /*
	 * NOTE: It is important not to set the modified bit
	 *	 until after we have acquired the bp or we risk
	 *	 racing against checkwrite.
	 */
	hammer_lock_ex(&io->lock);
	if (io->modified == 0) {
		hammer_io_set_modlist(io);
		io->modified = 1;
	}
	if (io->released) {
		/* regetblk(io->bp);
		BUF_KERNPROC(io->bp); */
		io->released = 0;
	}
	if (io->modified == 0) {
		hammer_io_set_modlist(io);
		io->modified = 1;

		KKASSERT(io->modified != 0);
	}
	hammer_unlock(&io->lock);
}

static __inline
void
hammer_io_modify_done(hammer_io_t io)
{
   /* panic("hammer_io_modify_done"); */

	KKASSERT(io->modify_refs > 0);
	--io->modify_refs;
	if (io->modify_refs == 0 && io->waitmod) {
		io->waitmod = 0;
		wakeup(io);
	}
}

/*
 * The write interlock blocks other threads trying to modify a buffer
 * (they block in hammer_io_modify()) after us, or blocks us while other
 * threads are in the middle of modifying a buffer.
 *
 * The caller also has a ref on the io, however if we are not careful
 * we will race bioops callbacks (checkwrite).  To deal with this
 * we must at least acquire and release the io_token, and it is probably
 * better to hold it through the setting of modify_refs.
 */
void
hammer_io_write_interlock(hammer_io_t io)
{
   /* panic("hammer_io_write_interlock"); */
    // XXX hammer_mount_t hmp = io->hmp;
    crit_enter();
    while (io->modify_refs != 0) {
        io->waitmod = 1;
	tsleep(io, 0, "hmrmod", 0);
    }
    io->modify_refs = -1;
    crit_exit();
}

void
hammer_io_done_interlock(hammer_io_t io)
{
   /* panic("hammer_io_done_interlock"); */
	KKASSERT(io->modify_refs == -1);
	io->modify_refs = 0;
	if (io->waitmod) {
		io->waitmod = 0;
		wakeup(io);
	}
}

/*
 * Caller intends to modify a volume's ondisk structure.
 *
 * This is only allowed if we are the flusher or we have a ref on the
 * sync_lock.
 */
void
hammer_modify_volume(hammer_transaction_t trans, hammer_volume_t volume,
		     void *base, int len)
{
   /* panic("hammer_modify_volume"); */
        long rel_offset;
	KKASSERT (trans == NULL || trans->sync_lock_refs > 0);
        
	hammer_io_modify(&volume->io, 1);
	if (len) {
		rel_offset = (long)base - (long)volume->ondisk;
		KKASSERT((rel_offset & ~(long)HAMMER_BUFMASK) == 0);
		 hammer_generate_undo(trans,
                         HAMMER_ENCODE_RAW_VOLUME(volume->vol_no, rel_offset),
                         base, len);
	}
}

/*
 * Caller intends to modify a buffer's ondisk structure.
 *
 * This is only allowed if we are the flusher or we have a ref on the
 * sync_lock.
 */
void
hammer_modify_buffer(hammer_transaction_t trans, hammer_buffer_t buffer,
		     void *base, int len)
{
   /* panic("hammer_modify_buffer"); */
 
	KKASSERT (trans == NULL || trans->sync_lock_refs > 0);

	hammer_io_modify(&buffer->io, 1);
	if (len) {
		long rel_offset = (long)base - (long)buffer->ondisk;
		KKASSERT((rel_offset & ~(long)HAMMER_BUFMASK) == 0);
		hammer_generate_undo(trans,
                                     buffer->zone2_offset + rel_offset,
                                     base, len);
	}
}

void
hammer_modify_volume_done(hammer_volume_t volume)
{
	hammer_io_modify_done(&volume->io);
}

void
hammer_modify_buffer_done(hammer_buffer_t buffer)
{
	hammer_io_modify_done(&buffer->io);
}

/*
 * Mark an entity as not being dirty any more and finalize any
 * delayed adjustments to the buffer.
 *
 * Delayed adjustments are an important performance enhancement, allowing
 * us to avoid recalculating B-Tree node CRCs over and over again when
 * making bulk-modifications to the B-Tree.
 *
 * If inval is non-zero delayed adjustments are ignored.
 *
 * This routine may dereference related btree nodes and cause the
 * buffer to be dereferenced.  The caller must own a reference on io.
 */
void
hammer_io_clear_modify(struct hammer_io *io, int inval)
{
	/* hammer_mount_t hmp; */

	/*
	 * io_token is needed to avoid races on mod_list
	 */
	if (io->modified == 0)
		return;
	/* hmp = io->hmp; */
	crit_enter();
	if (io->modified == 0) {
		crit_exit();
		return;
	}

	/*
	 * Take us off the mod-list and clear the modified bit.
	 */
	KKASSERT(io->mod_list != NULL);
	if (io->mod_list == &io->hmp->volu_list ||
	    io->mod_list == &io->hmp->meta_list) {
		io->hmp->locked_dirty_space -= io->bytes;
		hammer_count_dirtybufspace -= io->bytes;
	}
	TAILQ_REMOVE(io->mod_list, io, mod_entry);
	io->mod_list = NULL;
	io->modified = 0;
	
        crit_exit();
	/*
	 * If this bit is not set there are no delayed adjustments.
	 */
	if (io->gencrc == 0)
		return;
	io->gencrc = 0;

	/*
	 * Finalize requested CRCs.  The NEEDSCRC flag also holds a reference
	 * on the node (& underlying buffer).  Release the node after clearing
	 * the flag.
	 */
	if (io->type == HAMMER_STRUCTURE_META_BUFFER) {
		hammer_buffer_t buffer = (void *)io;
		hammer_node_t node;

restart:
		TAILQ_FOREACH(node, &buffer->clist, entry) {
			if ((node->flags & HAMMER_NODE_NEEDSCRC) == 0)
				continue;
			node->flags &= ~HAMMER_NODE_NEEDSCRC;
			KKASSERT(node->ondisk);
			if (inval == 0)
				node->ondisk->crc = crc32(&node->ondisk->crc + 1, HAMMER_BTREE_CRCSIZE);
			hammer_rel_node(node);
			goto restart;
		}
	}
	/* caller must still have ref on io */
	KKASSERT(io->lock.refs > 0);
}

/*
 * Clear the IO's modify list.  Even though the IO is no longer modified
 * it may still be on the lose_list.  This routine is called just before
 * the governing hammer_buffer is destroyed.
 *
 * mod_list requires io_token protection.
 */
void
hammer_io_clear_modlist(struct hammer_io *io)
{
   /* panic("hammer_io_clear_modlist"); */
    // XX hammer_mount_t hmp = io->hmp;

	KKASSERT(io->modified == 0);

	if (io->mod_list) {
		crit_enter();	/* biodone race against list */
		KKASSERT(io->mod_list == &io->hmp->lose_list);
		TAILQ_REMOVE(io->mod_list, io, mod_entry);
		io->mod_list = NULL;
		crit_exit();
	}
}

static void
hammer_io_set_modlist(struct hammer_io *io)
{
   /* panic("hammer_io_set_modlist"); */

	struct hammer_mount *hmp = io->hmp;
	
        crit_enter();	/* biodone race against list */
	KKASSERT(io->mod_list == NULL);

	switch(io->type) {
	case HAMMER_STRUCTURE_VOLUME:
		io->mod_list = &hmp->volu_list;
		hmp->locked_dirty_space += io->bytes;
		hammer_count_dirtybufspace += io->bytes;
		++hammer_count_io_locked;
		/* atomic_add_int(&hammer_count_dirtybufspace, io->bytes); */
		break;
	case HAMMER_STRUCTURE_META_BUFFER:
		io->mod_list = &hmp->meta_list;
		hmp->locked_dirty_space += io->bytes;
		hammer_count_dirtybufspace += io->bytes;
		++hammer_count_io_locked;
		/* atomic_add_int(&hammer_count_dirtybufspace, io->bytes); */
		break;
	case HAMMER_STRUCTURE_UNDO_BUFFER:
		io->mod_list = &hmp->undo_list;
		break;
	case HAMMER_STRUCTURE_DATA_BUFFER:
		io->mod_list = &hmp->data_list;
		break;
	case HAMMER_STRUCTURE_DUMMY:
		panic("hammer_io_disassociate: bad io type");
		break;
	}
	TAILQ_INSERT_TAIL(io->mod_list, io, mod_entry);
	crit_exit();
}

/************************************************************************
 *				HAMMER_BIOOPS				*
 ************************************************************************
 *
 */

/*
 * Pre-IO initiation kernel callback - cluster build only
 *
 * bioops callback - hold io_token
 */
static void
hammer_io_start(struct buf *bp)
{
	/* nothing to do, so io_token not needed */
}

/*
 * Post-IO completion kernel callback - MAY BE CALLED FROM INTERRUPT!
 *
 * NOTE: HAMMER may modify a data buffer after we have initiated write
 *	 I/O.
 *
 * NOTE: MPSAFE callback
 *
 * bioops callback - hold io_token
 */

static void
hammer_io_complete(struct buffer_head *bp)
{
// XXXXXXXXXXXXXXXXXXXXXXXX

	union hammer_io_structure *iou=(void *)bp; //(void *)LIST_FIRST(bp);
	struct hammer_mount *hmp = iou->io.hmp;
	struct hammer_io *ionext;

	crit_enter();	/* biodone race against list */

	KKASSERT(iou->io.released == 1);

	/*
	 * Deal with people waiting for I/O to drain
	 */
	if (iou->io.running) {
		/*
		 * Deal with critical write errors.  Once a critical error
		 * has been flagged in hmp the UNDO FIFO will not be updated.
		 * That way crash recover will give us a consistent
		 * filesystem.
		 *
		 * Because of this we can throw away failed UNDO buffers.  If
		 * we throw away META or DATA buffers we risk corrupting
		 * the now read-only version of the filesystem visible to
		 * the user.  Clear B_ERROR so the buffer is not re-dirtied
		 * by the kernel and ref the io so it doesn't get thrown
		 * away.
		 */
		if (bp->b_state & B_ERROR) {
		        crit_enter();
			hammer_critical_error(hmp, NULL, bp->b_state,
					      "while flushing meta-data");
			crit_exit();
			switch(iou->io.type) {
			case HAMMER_STRUCTURE_UNDO_BUFFER:
				break;
			default:
				if (iou->io.ioerror == 0) {
					iou->io.ioerror = 1;
					if (iou->io.lock.refs == 0)
						++hammer_count_refedbufs;
					hammer_ref(&iou->io.lock);
				}
				break;
			}
			bp->b_state &= ~B_ERROR;
			/* bundirty(bp); */
#if 0
			hammer_io_set_modlist(&iou->io);
			iou->io.modified = 1;
#endif
		}
		hammer_stats_disk_write += iou->io.bytes;
		++hammer_count_io_locked;
		/* atomic_add_int(&hammer_count_io_running_write, -iou->io.bytes);
		atomic_add_int(&hmp->io_running_space, -iou->io.bytes); */

		hammer_count_io_running_write -= iou->io.bytes;
		iou->io.hmp->io_running_space -= iou->io.bytes;
		
		if (hmp->io_running_wakeup &&
		    hmp->io_running_space < hammer_limit_running_io / 2) {
		    hmp->io_running_wakeup = 0;
		    wakeup(&hmp->io_running_wakeup);
		}
		KKASSERT(hmp->io_running_space >= 0);

		/* if (iou->io.hmp->io_running_space == 0)
			wakeup(&iou->io.hmp->io_running_space);
		KKASSERT(iou->io.hmp->io_running_space >= 0); */
		iou->io.running = 0;
		
	        /*
		 * Remove from iorun list and wakeup any multi-io waiter(s).
		 */
		if (TAILQ_FIRST(&hmp->iorun_list) == &iou->io) {
			ionext = TAILQ_NEXT(&iou->io, iorun_entry);
			if (ionext && ionext->type == HAMMER_STRUCTURE_DUMMY)
				wakeup(ionext);
		}
		TAILQ_REMOVE(&hmp->iorun_list, &iou->io, iorun_entry);
	} else {
		hammer_stats_disk_read += iou->io.bytes;
	}

	if (iou->io.waiting) {
		iou->io.waiting = 0;
		wakeup(iou);
	}

	/*
	 * If B_LOCKED is set someone wanted to deallocate the bp at some
	 * point, try to do it now.  The operation will fail if there are
	 * refs or if hammer_io_deallocate() is unable to gain the
	 * interlock.
	 */

	if ((bp->b_state & B_LOCKED) && iou->io.lock.refs == 0) {
		KKASSERT(iou->io.modified == 0);
		/* atomic_add_int(&hammer_count_io_locked, -1); */
		--hammer_count_io_locked;
		bp->b_state &= ~B_LOCKED;
		hammer_io_deallocate(bp);
		/* structure may be dead now */
	}

	crit_exit();
}


/*
 * Callback from kernel when it wishes to deallocate a passively
 * associated structure.  This mostly occurs with clean buffers
 * but it may be possible for a holding structure to be marked dirty
 * while its buffer is passively associated.  The caller owns the bp.
 *
 * If we cannot disassociate we set B_LOCKED to prevent the buffer
 * from getting reused.
 *
 * WARNING: Because this can be called directly by getnewbuf we cannot
 * recurse into the tree.  If a bp cannot be immediately disassociated
 * our only recourse is to set B_LOCKED.
 *
 * WARNING: This may be called from an interrupt via hammer_io_complete()
 *
 * bioops callback - hold io_token
 */
static void
hammer_io_deallocate(struct buffer_head *bp)
{
// XXX
#if 0
	hammer_io_structure_t iou = (void *)LIST_FIRST(&bp->b_dep);
	hammer_mount_t hmp;

	hmp = iou->io.hmp;

	crit_enter();


	KKASSERT((bp->b_flags & B_LOCKED) == 0 && iou->io.running == 0);
	/* if (iou->io.lock.refs > 0 || iou->io.modified) { */
	if (hammer_try_interlock_norefs(&iou->io.lock) == 0) {
		/*
		 * We cannot safely disassociate a bp from a referenced
		 * or interlocked HAMMER structure.
		 */
		bp->b_flags |= B_LOCKED;
		++hammer_count_io_locked;
		/* atomic_add_int(&hammer_count_io_locked, 1); */
	} else if (iou->io.modified) {
		/*
		 * It is not legal to disassociate a modified buffer.  This
		 * case really shouldn't ever occur.
		 */
		bp->b_flags |= B_LOCKED;
		++hammer_count_io_locked;
		/* 		atomic_add_int(&hammer_count_io_locked, 1); */
		hammer_put_interlock(&iou->io.lock, 0);
	} else {
		/*
		 * Disassociate the BP.  If the io has no refs left we
		 * have to add it to the loose list.  The kernel has
		 * locked the buffer and therefore our io must be
		 * in a released state.
		 */
		hammer_io_disassociate(iou);
		if (iou->io.type != HAMMER_STRUCTURE_VOLUME) {
			KKASSERT(iou->io.bp == NULL);
			KKASSERT(iou->io.mod_list == NULL);
			iou->io.mod_list = &hmp->lose_list;
			crit_enter();	/* biodone race against list */
			/* iou->io.mod_list = &iou->io.hmp->lose_list; */
			TAILQ_INSERT_TAIL(iou->io.mod_list, &iou->io, mod_entry);
			crit_exit();
		}
		hammer_put_interlock(&iou->io.lock, 1);
	}
#endif
	crit_exit();
}

/*
 * bioops callback - hold io_token
 */
static int
hammer_io_fsync(struct vnode *vp)
{
	/* nothing to do, so io_token not needed */
	return(0);
}

/*
 * NOTE: will not be called unless we tell the kernel about the
 * bioops.  Unused... we use the mount's VFS_SYNC instead.
 *
 * bioops callback - hold io_token
 */
static int
hammer_io_sync(struct mount *mp)
{
	/* nothing to do, so io_token not needed */
	return(0);
}

/*
 * bioops callback - hold io_token
 */
static void
hammer_io_movedeps(struct buf *bp1, struct buf *bp2)
{
	/* nothing to do, so io_token not needed */
}

/*
 * I/O pre-check for reading and writing.  HAMMER only uses this for
 * B_CACHE buffers so checkread just shouldn't happen, but if it does
 * allow it.
 *
 * Writing is a different case.  We don't want the kernel to try to write
 * out a buffer that HAMMER may be modifying passively or which has a
 * dependancy.  In addition, kernel-demanded writes can only proceed for
 * certain types of buffers (i.e. UNDO and DATA types).  Other dirty
 * buffer types can only be explicitly written by the flusher.
 *
 * checkwrite will only be called for bdwrite()n buffers.  If we return
 * success the kernel is guaranteed to initiate the buffer write.
 *
 * bioops callback - hold io_token
 */
static int
hammer_io_checkread(struct buf *bp)
{
/* nothing to do, so io_token not needed */

	return(0);
}

/*
 * The kernel is asking us whether it can write out a dirty buffer or not.
 *
 * bioops callback - hold io_token
 */
static int
hammer_io_checkwrite(struct buf *bp)
{
#if 0
	hammer_io_t io = (void *)LIST_FIRST(&bp->b_dep);
	hammer_mount_t hmp = io->hmp;

	/*
	 * This shouldn't happen under normal operation.
	 */
	crit_enter();
	if (io->type == HAMMER_STRUCTURE_VOLUME ||
	    io->type == HAMMER_STRUCTURE_META_BUFFER) {
		if (!panicstr)
			panic("hammer_io_checkwrite: illegal buffer");
		if ((bp->b_flags & B_LOCKED) == 0) {
			bp->b_flags |= B_LOCKED;
			++hammer_count_io_locked;
		        /*atomic_add_int(&hammer_count_io_locked, 1); */
		}
		crit_exit;
		return(1);
	}

        /*
	 * We have to be able to interlock the IO to safely modify any
	 * of its fields without holding the fs_token.  If we can't lock
	 * it then we are racing someone.
	 *
	 * Our ownership of the bp lock prevents the io from being ripped
	 * out from under us.
	 */
	if (hammer_try_interlock_norefs(&io->lock) == 0) {
		bp->b_flags |= B_LOCKED;
		++hammer_count_io_locked;
		/* atomic_add_int(&hammer_count_io_locked, 1); */
		crit_exit();
		return(1);
	}

	/*
	 * The modified bit must be cleared prior to the initiation of
	 * any IO (returning 0 initiates the IO).  Because this is a
	 * normal data buffer hammer_io_clear_modify() runs through a
	 * simple degenerate case.
	 *
	 * Return 0 will cause the kernel to initiate the IO, and we
	 * must normally clear the modified bit before we begin.  If
	 * the io has modify_refs we do not clear the modified bit,
	 * otherwise we may miss changes.
	 *
	 * Only data and undo buffers can reach here.  These buffers do
	 * not have terminal crc functions but we temporarily reference
	 * the IO anyway, just in case.
	 */
	if (io->modify_refs == 0 && io->modified) {
		hammer_ref(&io->lock);
		hammer_io_clear_modify(io, 0);
		hammer_rel(&io->lock);
		/* hammer_unref(&io->lock); */
	} else if (io->modified) {
		KKASSERT(io->type == HAMMER_STRUCTURE_DATA_BUFFER);
	}

	/*
	 * The kernel is going to start the IO, set io->running.
	 */
	KKASSERT(io->running == 0);
	io->running = 1;
	io->hmp->io_running_space += io->bytes;
	hammer_count_io_running_write += io->bytes;
	TAILQ_INSERT_TAIL(&io->hmp->iorun_list, io, iorun_entry);

	hammer_put_interlock(&io->lock, 1);
	
#endif
        crit_exit();

	return(0);
}

/*
 * Return non-zero if we wish to delay the kernel's attempt to flush
 * this buffer to disk.
 *
 * bioops callback - hold io_token
 */
static int
hammer_io_countdeps(struct buf *bp, int n)
{
	/* nothing to do, so io_token not needed */
	return(0);
}

struct bio_ops hammer_bioops = {
	.io_start	= hammer_io_start,
	.io_complete	= hammer_io_complete, 
        .io_direct_read_complete = hammer_io_direct_read_complete,
	.io_deallocate	= hammer_io_deallocate,
	.io_fsync	= hammer_io_fsync,
	.io_sync	= hammer_io_sync,
	.io_movedeps	= hammer_io_movedeps,
	.io_countdeps	= hammer_io_countdeps,
	.io_checkread	= hammer_io_checkread,
	.io_checkwrite	= hammer_io_checkwrite,
};

struct hammer_dio_private {
        struct inode *inode;
        u64 logical_offset;
        u64 disk_bytenr;
        u64 bytes;
        u32 *csums;
        void *private;

        /* number of bios pending for this dio */
        atomic_t pending_bios;

        /* IO errors */
        int errors;

        struct bio *orig_bio;
};


/************************************************************************
 *				DIRECT IO OPS 				*
 ************************************************************************
 *
 * These functions operate directly on the buffer cache buffer associated
 * with a front-end vnode rather then a back-end device vnode.
 */

/*
 * Read a buffer associated with a front-end vnode directly from the
 * disk media.  The bio may be issued asynchronously.  If leaf is non-NULL
 * we validate the CRC.
 *
 * We must check for the presence of a HAMMER buffer to handle the case
 * where the reblocker has rewritten the data (which it does via the HAMMER
 * buffer system, not via the high-level vnode buffer cache), but not yet
 * committed the buffer to the media. 
 */
int
hammer_io_direct_read(hammer_mount_t hmp, struct bio *bio,
		      hammer_btree_leaf_elm_t leaf)
{
        struct hammer_dio_private *dip = bio->bi_private;
      /*  struct bio_vec *bvec_end = bio->bi_io_vec + bio->bi_vcnt - 1;
        struct bio_vec *bvec = bio->bi_io_vec; */
        struct buffer_head *bh_result=(void *)bio;
	hammer_off_t buf_offset;
	hammer_off_t zone2_offset;
	hammer_volume_t volume;
	struct buf *bp=(void *)bio;
	struct bio_vec *nbio=(void *)bio;
	int vol_no;
	int error;

	/* buf_offset = bio->bio_offset; */
	buf_offset = dip->logical_offset;
	KKASSERT((buf_offset & HAMMER_OFF_ZONE_MASK) ==
		 HAMMER_ZONE_LARGE_DATA);

	/*
	 * The buffer cache may have an aliased buffer (the reblocker can
	 * write them).  If it does we have to sync any dirty data before
	 * we can build our direct-read.  This is a non-critical code path.
	 */
	/* bp = bio->bio_buf; */
	hammer_sync_buffers(hmp, buf_offset, bh_result->b_size);

	/*
	 * Resolve to a zone-2 offset.  The conversion just requires
	 * munging the top 4 bits but we want to abstract it anyway
	 * so the blockmap code can verify the zone assignment.
	 */
	zone2_offset = hammer_blockmap_lookup(hmp, buf_offset, &error);
	if (error)
		goto done;
	KKASSERT((zone2_offset & HAMMER_OFF_ZONE_MASK) ==
		 HAMMER_ZONE_RAW_BUFFER);

	/*
	 * Resolve volume and raw-offset for 3rd level bio.  The
	 * offset will be specific to the volume.
	 */
	vol_no = HAMMER_VOL_DECODE(zone2_offset);
	volume = hammer_get_volume(hmp, vol_no, &error);
	if (error == 0 && zone2_offset >= volume->maxbuf_off)
		error = EIO;

	if (error == 0) {
		/*
		 * 3rd level bio
		 */
		/* XXX nbio = push_bio(bio); */
		nbio->bv_offset = volume->ondisk->vol_buf_beg +
				   (zone2_offset & HAMMER_OFF_SHORT_MASK);
#if 0
		/*
		 * XXX disabled - our CRC check doesn't work if the OS
		 * does bogus_page replacement on the direct-read.
		 */
		if (leaf && hammer_verify_data) {
			nbio->bio_done = hammer_io_direct_read_complete;
			nbio->bio_caller_info1.uvalue32 = leaf->data_crc;
		}
#endif
		hammer_stats_disk_read += bh_result->b_size; /* bp->b_bufsize; */
		/* XXX Block acess ASYNC vn_strategy(volume->devvp, nbio); */
	}
	hammer_rel_volume(volume, 0);
done:
	if (error) {
		kprintf("hammer_direct_read: failed @ %016llx\n",
			zone2_offset);
		bp->b_error = error;
		bp->b_flags |= B_ERROR;
		/* XXX biodone(bio); */
	}
	return(error);

}


/*
 * On completion of the BIO this callback must check the data CRC
 * and chain to the previous bio.
 *
 * MPSAFE - since we do not modify and hammer_records we do not need
 *	    io_token.
 *
 * NOTE: MPSAFE callback
 */
static
void
hammer_io_direct_read_complete(struct bio *nbio)
{
#if 0
	struct bio *obio;
	struct buf *bp;
	struct buffer_head *bh_result;
	u_int32_t rec_crc = nbio->bio_caller_info1.uvalue32;

	bp = nbio->bio_buf;
	if (crc32(bp->b_data, bh_result->b_size) != rec_crc) {
		kprintf("HAMMER: data_crc error @%016llx/%d\n",
			nbio->bio_offset, bh_result->b_size);
		if (hammer_debug_critical)
			Debugger("data_crc on read");

		bp->b_flags |= B_ERROR;
		bp->b_error = EIO;
	}
	obio = pop_bio(nbio);
	biodone(obio);
#endif
        printk("hammer_io_direct_read_complete\n");
}


/*
 * Write a buffer associated with a front-end vnode directly to the
 * disk media.  The bio may be issued asynchronously.
 *
 * The BIO is associated with the specified record and RECF_DIRECT_IO
 * is set.  The recorded is added to its object.
 hammer_io_direct_write(hammer_mount_t hmp, hammer_record_t record,
		       struct bio *bio)
 */
int
hammer_io_direct_write(hammer_mount_t hmp, struct bio *bio,
		       hammer_record_t record)
{
	hammer_btree_leaf_elm_t leaf = &record->leaf;
	hammer_off_t buf_offset;
	hammer_off_t zone2_offset;
	hammer_volume_t volume;
	hammer_buffer_t buffer;
	struct buffer_head *bh_result=(void *)bio;
	struct buf *bp=(void *)bio;
	struct bio_vec *nbio=(void *)bio;
	char *ptr;
	int vol_no;
	int error;

	buf_offset = leaf->data_offset;

	KKASSERT(buf_offset > HAMMER_ZONE_BTREE);
	/* XX KKASSERT(bio->bio_buf->b_cmd == BUF_CMD_WRITE); */

        /*
	 * Issue or execute the I/O.  The new memory record must replace
	 * the old one before the I/O completes, otherwise a reaquisition of
	 * the buffer will load the old media data instead of the new.
	 */
	if ((buf_offset & HAMMER_BUFMASK) == 0 && leaf->data_len >= HAMMER_BUFSIZE) {
		/*
		 * We are using the vnode's bio to write directly to the
		 * media, any hammer_buffer at the same zone-X offset will
		 * now have stale data.
		 */
		zone2_offset = hammer_blockmap_lookup(hmp, buf_offset, &error);
		vol_no = HAMMER_VOL_DECODE(zone2_offset);
		volume = hammer_get_volume(hmp, vol_no, &error);

		if (error == 0 && zone2_offset >= volume->maxbuf_off)
			error = EIO;
		if (error == 0) {
			/* bp = bio->bio_buf; */
			KKASSERT((bh_result->b_size & HAMMER_BUFMASK) == 0);
			hammer_del_buffers(hmp, buf_offset,zone2_offset, bh_result->b_size, 1);
					   
			/*
			 * Second level bio - cached zone2 offset.
			 *
			 * (We can put our bio_done function in either the
			 *  2nd or 3rd level).
			 */
			/* XXX nbio = push_bio(bio); */
			nbio->bv_offset = zone2_offset;
			/* nbio->bio_done = hammer_io_direct_write_complete; 
			nbio->bv_page = record; XXX */
			record->zone2_offset = zone2_offset;
			record->flags |= HAMMER_RECF_DIRECT_IO |
					 HAMMER_RECF_DIRECT_INVAL;

			/*
			 * Third level bio - raw offset specific to the
			 * correct volume.
			 */
			zone2_offset &= HAMMER_OFF_SHORT_MASK;
			/* XXX nbio = push_bio(nbio); */
			nbio->bv_offset = volume->ondisk->vol_buf_beg +
					   zone2_offset;
			hammer_stats_disk_write += bh_result->b_size;
			hammer_ip_replace_bulk(hmp, record);
			/* XXX vn_strategy(volume->devvp, nbio); */
			hammer_io_flush_mark(volume);
		}
		hammer_rel_volume(volume, 0);
	} else {
		/* 
		 * Must fit in a standard HAMMER buffer.  In this case all
		 * consumers use the HAMMER buffer system and RECG_DIRECT_IO
		 * does not need to be set-up.
		 */
		KKASSERT(((buf_offset ^ (buf_offset + leaf->data_len - 1)) & ~HAMMER_BUFMASK64) == 0);
		buffer = NULL;
		ptr = hammer_bread(hmp, buf_offset, &error, &buffer);
		if (error == 0) {
			/* bp = bio->bio_buf; */
			bp->b_flags |= B_AGE;
			hammer_io_modify(&buffer->io, 1);
			bcopy(bp->b_data, ptr, leaf->data_len);
			hammer_io_modify_done(&buffer->io);
			hammer_rel_buffer(buffer, 0);
			bp->b_resid = 0;
			hammer_ip_replace_bulk(hmp, record);
			/* XX biodone(bio); */
		}
	}
	if (error == 0) {
		/*
		 * The record is all setup now, add it.  Potential conflics
		 * have already been dealt with.
		 */
		error = hammer_mem_add(record);
		KKASSERT(error == 0);
	} else {
		/*
		 * Major suckage occured.
		 */
		kprintf("hammer_direct_write: failed @ %016llx\n",
			(long long)leaf->data_offset);
		/* bp = bio->bio_buf; */
		bp->b_resid = 0;
		bp->b_error = EIO;
		bp->b_flags |= B_ERROR;
		/* biodone(bio); */
		record->flags |= HAMMER_RECF_DELETED_FE;
		hammer_rel_mem_record(record);
	}
	return(error);
}

/*
 * On completion of the BIO this callback must disconnect
 * it from the hammer_record and chain to the previous bio.
 *
 * An I/O error forces the mount to read-only.  Data buffers
 * are not B_LOCKED like meta-data buffers are, so we have to
 * throw the buffer away to prevent the kernel from retrying.
 *
 * NOTE: MPSAFE callback, only modify fields we have explicit
 *	 access to (the bp and the record->gflags).
 */
/*
static
void
hammer_io_direct_write_complete(struct bio_vec *nbio)
{
#if 0
	* not used struct bio *obio; *
	struct buf *bp;
	hammer_record_t record = nbio->bv_page; * nbio->bio_caller_info1.ptr; *
	hammer_mount_t hmp;

	KKASSERT(record != NULL);
	hmp = record->ip->hmp;

        crit_enter();

	bp = nbio->bio_buf;
	obio = pop_bio(nbio);
	if (bp->b_flags & B_ERROR) {
		hammer_critical_error(hmp, record->ip,
				      bp->b_error,
				      "while writing bulk data");
		bp->b_flags |= B_INVAL;
	}
	biodone(obio); 

	KKASSERT(record != NULL); 
        KKASSERT(record->gflags & HAMMER_RECG_DIRECT_IO);
	KKASSERT(record->flags & HAMMER_RECF_DIRECT_IO);
	record->flags &= ~HAMMER_RECF_DIRECT_IO;
	if (record->gflags & HAMMER_RECG_DIRECT_WAIT) {
		record->gflags &= ~(HAMMER_RECG_DIRECT_IO |
				    HAMMER_RECG_DIRECT_WAIT);
		* record can disappear once DIRECT_IO flag is cleared *
		wakeup(&record->flags);
	} else {
		record->gflags &= ~HAMMER_RECG_DIRECT_IO;
		* record can disappear once DIRECT_IO flag is cleared *
	}
#endif 
        printk("hammer_io_direct_write_complete\n");
}
*/


/*
 * This is called before a record is either committed to the B-Tree
 * or destroyed, to resolve any associated direct-IO. 
 *
 * (1) We must wait for any direct-IO related to the record to complete.
 *
 * (2) We must remove any buffer cache aliases for data accessed via
 *     leaf->data_offset or zone2_offset so non-direct-IO consumers  
 *     (the mirroring and reblocking code) do not see stale data.
 */
void
hammer_io_direct_wait(hammer_record_t record)
{
 /*   panic("hammer_io_direct_wait"); */
    	hammer_mount_t hmp = record->ip->hmp;

	/*
	 * Wait for I/O to complete
	 */
	if (record->gflags & HAMMER_RECG_DIRECT_IO) {
		crit_enter();
		while (record->gflags & HAMMER_RECG_DIRECT_IO) {
			record->gflags |= HAMMER_RECG_DIRECT_WAIT;
			tsleep(&record->flags, 0, "hmdiow", 0);
		}
		crit_exit();
	}

	/*
	 * Invalidate any related buffer cache aliases associated with the
	 * backing device.  This is needed because the buffer cache buffer
	 * for file data is associated with the file vnode, not the backing
	 * device vnode.
	 *
	 * XXX I do not think this case can occur any more now that
	 * reservations ensure that all such buffers are removed before
	 * an area can be reused.
	 */
	if (record->gflags & HAMMER_RECG_DIRECT_INVAL) {
		KKASSERT(record->leaf.data_offset);
		hammer_del_buffers(hmp, record->leaf.data_offset,
				   record->zone2_offset, record->leaf.data_len,1);
				   
		record->gflags &= ~HAMMER_RECG_DIRECT_INVAL;
	}
}

/*
 * This is called to remove the second-level cached zone-2 offset from
 * frontend buffer cache buffers, now stale due to a data relocation.
 * These offsets are generated by cluster_read() via VOP_BMAP, or directly
 * by hammer_vop_strategy_read().
 *
 * This is rather nasty because here we have something like the reblocker
 * scanning the raw B-Tree with no held references on anything, really,
 * other then a shared lock on the B-Tree node, and we have to access the
 * frontend's buffer cache to check for and clean out the association.
 * Specifically, if the reblocker is moving data on the disk, these cached
 * offsets will become invalid.
 *
 * Only data record types associated with the large-data zone are subject
 * to direct-io and need to be checked.
 *
 */
void
hammer_io_direct_uncache(hammer_mount_t hmp, hammer_btree_leaf_elm_t leaf)
{
/*    panic("hammer_io_direct_uncache"); */

	struct hammer_inode_info iinfo;
	int zone;

	if (leaf->base.rec_type != HAMMER_RECTYPE_DATA)
		return;
	zone = HAMMER_ZONE_DECODE(leaf->data_offset);
	if (zone != HAMMER_ZONE_LARGE_DATA_INDEX)
		return;
	iinfo.obj_id = leaf->base.obj_id;
	iinfo.obj_asof = 0;	/* unused */
	iinfo.obj_localization = leaf->base.localization &
				 HAMMER_LOCALIZE_PSEUDOFS_MASK;
	iinfo.u.leaf = leaf;
	hammer_scan_inode_snapshots(hmp, &iinfo,
				    hammer_io_direct_uncache_callback,
				    leaf);

}

static int
hammer_io_direct_uncache_callback(hammer_inode_t ip, void *data)
{
   /* panic("hammer_io_direct_uncache_callback"); */

	hammer_inode_info_t iinfo = data;
	 /* hammer_off_t data_offset; 
	hammer_off_t file_offset; */
	struct vnode *vp;
	/* struct buf *bp; */
	int blksize;

	if (ip->vp == NULL)
		return(0);
	/* data_offset = iinfo->u.leaf->data_offset;
	file_offset = iinfo->u.leaf->base.key - iinfo->u.leaf->data_len; */
	blksize = iinfo->u.leaf->data_len;
	KKASSERT((blksize & HAMMER_BUFMASK) == 0);
	
        /*
	 * Warning: FINDBLK_TEST return stable storage but not stable
	 *	    contents.  It happens to be ok in this case.
	 */
	hammer_ref(&ip->lock);
	if (hammer_get_vnode(ip, &vp) == 0) {
/*	XXX	if ((bp = findblk(ip->vp, file_offset, FINDBLK_TEST)) != NULL &&
		    bp->b_bio2.bio_offset != NOOFFSET) {
			bp = getblk(ip->vp, file_offset, blksize, 0, 0);
			bp->b_bio2.bio_offset = NOOFFSET;
			brelse(bp);
		} 
		vput(vp); */
	}
	hammer_rel_inode(ip, 0);

	return(0);
}


/*
 * This function is called when writes may have occured on the volume,
 * indicating that the device may be holding cached writes.
 */
static void
hammer_io_flush_mark(hammer_volume_t volume)
{
/* atomic_set_int(&volume->vol_flags, HAMMER_VOLF_NEEDFLUSH);*/
	volume->vol_flags |= HAMMER_VOLF_NEEDFLUSH;
}

/*
 * This function ensures that the device has flushed any cached writes out.
 */
void
hammer_io_flush_sync(hammer_mount_t hmp)
{
	hammer_volume_t volume;
	struct buf *bp_base = NULL;
	struct buf *bp=NULL;

        printk("hammer_io_flush_sync\n");
	RB_FOREACH(volume, hammer_vol_rb_tree, &hmp->rb_vols_root) {
		if (volume->vol_flags & HAMMER_VOLF_NEEDFLUSH) {
			volume->vol_flags &= ~HAMMER_VOLF_NEEDFLUSH;
			/* XX bp = getpbuf(NULL); */
/*			bp->b_bio1.bio_offset = 0;
			bp->b_bufsize = 0;
			bp->b_bcount = 0;
			bp->b_cmd = BUF_CMD_FLUSH; 
			bp->b_bio1.bio_caller_info1.cluster_head = bp_base;
			bp->b_bio1.bio_done = hammer_io_flush_sync_done; */
			/* bp->b_bio1.bio_done = biodone_sync; */
			bp->b_flags |= B_ASYNC;
			bp_base = bp;
			/* XXX vn_strategy(volume->devvp, &bp->b_bio1); */
		}
	}
	while ((bp = bp_base) != NULL) {
		/* bp_base = bp->b_bio1.bio_caller_info1.cluster_head; */
		/* XXX biowait(&bp->b_bio1, "hmrFLS"); 
		while (bp->b_cmd != BUF_CMD_DONE) {
			crit_enter();
			tsleep_interlock(&bp->b_cmd); 
			if (bp->b_cmd != BUF_CMD_DONE)
				tsleep(&bp->b_cmd, 0, "hmrFLS", 0);
			crit_exit();
		} */
		bp->b_flags &= ~B_ASYNC;
		/* relpbuf(bp, NULL); */
	}
}

/*
 * Limit the amount of backlog which we allow to build up
 */
void
hammer_io_limit_backlog(hammer_mount_t hmp)
{
        while (hmp->io_running_space > hammer_limit_running_io) {
                hmp->io_running_wakeup = 1;
                tsleep(&hmp->io_running_wakeup, 0, "hmiolm", hz / 10);
        }
}

/*
 * Callback to deal with completed flush commands to the device.
 */
/*
static void
hammer_io_flush_sync_done(struct bio *bio)
{
#if 0
	struct buf *bp;
#endif 
        printk("hammer_io_flush_sync_done");
	bp = bio->bio_buf;
	bp->b_cmd = BUF_CMD_DONE; 
	wakeup(&bp->b_cmd);
}
*/
