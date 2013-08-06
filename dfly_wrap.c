#include "dfly_wrap.h"
#include <linux/errno.h>

/* from sys/sysctl.h */
int desiredvnodes = KERN_MAXVNODES; /* Maximum number of vnodes */

/* from kern/vfs_nlookup.c */
int nlookup_init(struct nlookupdata *nd, const char *path,
				enum uio_seg seg, int flags)
{
	return 0;
}

int nlookup(struct nlookupdata *nd)
{
	return 0;
}

void nlookup_done(struct nlookupdata *nd)
{
	/* no-op */
}

/* from kern/vfs_subr.c */
int count_udev(int x, int y)
{
	return 0;
}

int vfs_mountedon(struct vnode *vp)
{
	return 0;
}

int vinvalbuf(struct vnode *vp, int flags, int slpflag, int slptimeo)
{
	return 0;
}

int vn_isdisk(struct vnode *vp, int *errp)
{
	return 1;
}

int vn_lock(struct vnode *vp, int flags)
{
	return 0;
}

void vn_unlock(struct vnode *vp)
{
	panic("vn_unlock");
}

/* from kern/vopops.c */
int vop_setattr(struct vop_ops *ops, struct vnode *vp, struct vattr *vap, struct ucred *cred)
{
	panic("vop_setattr");
	return 0;
}

int vop_open(struct vop_ops *ops, struct vnode *vp, int mode,struct ucred *cred,struct file *fp)
{
	panic("vop_open");
	return 0;
}

int vop_close(struct vop_ops *ops, struct vnode *vp, int fflag)
{
	panic("vop_close");
	return 0;
}

int vop_fsync(struct vop_ops *ops, struct vnode *vp, int waitfor)
{
	panic("vop_fsync");
	return 0;
}

/* from kern/vfs_lock.c */
void vrele(struct vnode *vp)
{
	panic("vrele");
}

/* from kern/vfs_cache.c */
int cache_vref(struct nchandle *nch, struct ucred *cred, struct vnode **vpp)
{
	return 0;
}

/* from platform///db_interface.c */
void Debugger(const char *msg)
{
	panic("Debugger");
}

/* from platform//platform/copyio.c */
int copyout(const void *kaddr, void *udaddr, size_t len)
{
	panic("copyout");
	return 0;
}

int copyin(const void *udaddr, void *kaddr, size_t len)
{
	panic("copyin");
	return 0;
}

/*
 * When initiating asynchronous I/O, change ownership of the lock to the
 * kernel. Once done, the lock may legally released by biodone. The
 * original owning process can no longer acquire it recursively, but must
 * wait until the I/O is completed and the lock has been freed by biodone.
 */
void BUF_KERNPROC(struct buf *bp)
{
	panic("BUF_KERNPROC");
	//lockmgr_kernproc(&(bp)->b_lock);
}

#define PINTERLOCKED    0x00000400      /* Interlocked tsleep */

int atomic_cmpset_int(volatile u_int *dst, u_int exp, u_int src)
{
	u_char res;

	asm volatile(
	"	pushfq ;		"
	"	cli ;			"
	"	cmpl	%3,%4 ;		"
	"	jne	1f ;		"
	"	movl	%2,%1 ;		"
	"1:				"
	"       sete	%0 ;		"
	"	popfq ;			"
	"# atomic_cmpset_int"
	: "=q" (res),			/* 0 */
	  "=m" (*dst)			/* 1 */
	: "r" (src),			/* 2 */
	  "r" (exp),			/* 3 */
	  "m" (*dst)			/* 4 */
	: "memory");

	return res;
}

/**
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v.
 */
/* static inline */ void atomic_add_long(long int *v, long i)
{
/*
         asm volatile(LOCK_PREFIX "addl %1,%0"
                      : "+m" (v->counter)
                      : "ir" (i));
*/
}

/*
* cpu_sfence() ensures strong write ordering for writes issued prior
* to the instruction verses writes issued afterwords.  Writes are
* ordered on intel cpus so we do not actually have to do anything.
*/
static inline void
cpu_sfence(void)
{
        /*
         * NOTE:
         * Don't use 'sfence' here, as it will create a lot of
         * unnecessary stalls.
         */
         asm volatile("" : : : "memory");
}

void
cpu_ccfence(void)
{
        /*
         * NOTE:
         * Don't use 'sfence' here, as it will create a lot of
         * unnecessary stalls.
         */
         asm volatile("" : : : "memory");
}

static inline long
atomic_cmpset_long(volatile u_long *_dst, u_long _old, u_long _new)
{
	u_long res = _old;

	/* asm volatile(MPLOCKED "cmpxchgq %2,%1; " */
	asm volatile("cmpxchgq %2,%1; " \
			 : "+a" (res), "=m" (*_dst) \
			 : "r" (_new), "m" (*_dst) \
			 : "memory");
	return (res == _old);
}

/*
 * Release a token that we hold.
 */
static inline
void
_lwkt_reltokref(lwkt_tokref_t ref, thread_t td)
{
	lwkt_token_t tok;
	long count;

	tok = ref->tr_tok;
	for (;;) {
		count = tok->t_count;
		cpu_ccfence();
		if (tok->t_ref == ref) {
			/*
			 * We are an exclusive holder.  We must clear tr_ref
			 * before we clear the TOK_EXCLUSIVE bit.  If we are
			 * unable to clear the bit we must restore
			 * tok->t_ref.
			 */
			KKASSERT(count & TOK_EXCLUSIVE);
			tok->t_ref = NULL;
			if (atomic_cmpset_long(&tok->t_count, count,
					       count & ~TOK_EXCLUSIVE)) {
				return;
			}
			tok->t_ref = ref;
			/* retry */
		} else {
			/*
			 * We are a shared holder
			 */
			KKASSERT(count & TOK_COUNTMASK);
			if (atomic_cmpset_long(&tok->t_count, count,
					       count - TOK_INCR)) {
				return;
			}
			/* retry */
		}
		/* retry */
	}
}


/*
 * Initialize a tokref_t prior to making it visible in the thread's
 * token array.
 */
static inline
void
_lwkt_tokref_init(lwkt_tokref_t ref, lwkt_token_t tok, thread_t td, long excl)
{
	ref->tr_tok = tok;
	ref->tr_count = excl;
	ref->tr_owner = td;
}

/*
 * Release a serializing token.
 *
 * WARNING!  All tokens must be released in reverse order.  This will be
 *	     asserted.
 */
void
lwkt_reltoken(lwkt_token_t tok)
{
	thread_t td = curthread;
	lwkt_tokref_t ref;

	/*
	 * Remove ref from thread token list and assert that it matches
	 * the token passed in.  Tokens must be released in reverse order.
	 */
	ref = td->td_toks_stop - 1;
	KKASSERT(ref >= &td->td_toks_base && ref->tr_tok == tok);
	_lwkt_reltokref(ref, td);
	cpu_sfence();
	td->td_toks_stop = ref;
}

void
lwkt_reltoken_hard(lwkt_token_t tok)
{
	lwkt_reltoken(tok);
	/* crit_exit_hard(); */
}


/*
 * Get a serializing token.  This routine can block.
 */
void
lwkt_gettoken(lwkt_token_t tok)
{
	panic("lwkt_gettoken");
/*
	thread_t td = curthread;
	lwkt_tokref_t ref;

	ref = td->td_toks_stop;
	KKASSERT(ref < &td->td_toks_end);
	++td->td_toks_stop;
	cpu_ccfence();
	_lwkt_tokref_init(ref, tok, td, TOK_EXCLUSIVE|TOK_EXCLREQ);


	if (_lwkt_trytokref_spin(ref, td, TOK_EXCLUSIVE|TOK_EXCLREQ))
		return;

	
	td->td_wmesg = tok->t_desc;
	++tok->t_collisions;
	logtoken(fail, ref);
	td->td_toks_have = td->td_toks_stop - 1;

	if (tokens_debug_output > 0) {
		--tokens_debug_output;
		spin_lock(&tok_debug_spin);
		kprintf("Excl Token thread %p %s %s\n",
			td, tok->t_desc, td->td_comm);
		print_backtrace(6);
		kprintf("\n");
		spin_unlock(&tok_debug_spin);
	}

	lwkt_switch();
	logtoken(succ, ref);
	KKASSERT(tok->t_ref == ref);
*/
}

/*
 * Similar to gettoken but we acquire a shared token instead of an exclusive
 * token.
 */
void
lwkt_gettoken_shared(lwkt_token_t tok)
{
	panic("lwkt_gettoken_shared");
/*
	thread_t td = curthread;
	lwkt_tokref_t ref;

	ref = td->td_toks_stop;

	++td->td_toks_stop;
	_lwkt_tokref_init(ref, tok, td, TOK_EXCLREQ);

	td->td_wmesg = tok->t_desc;
	++tok->t_collisions;
	logtoken(fail, ref);
	td->td_toks_have = td->td_toks_stop - 1;

	if (tokens_debug_output > 0) {
		--tokens_debug_output;
		spin_lock(&tok_debug_spin);
		kprintf("Shar Token thread %p %s %s\n",
			td, tok->t_desc, td->td_comm);
		print_backtrace(6);
		kprintf("\n");
		spin_unlock(&tok_debug_spin);
	}

	lwkt_switch();
	logtoken(succ, ref); */
}

/*
 * This is a dandy function that allows us to interlock tsleep/wakeup
 * operations with unspecified upper level locks, such as lockmgr locks,
 * simply by holding a critical section.  The sequence is:
 *
 *	(acquire upper level lock)
 *	tsleep_interlock(blah)
 *	(release upper level lock)
 *	tsleep(blah, ...)
 *
 * Basically this functions queues us on the tsleep queue without actually
 * descheduling us.  When tsleep() is later called with PINTERLOCK it
 * assumes the thread was already queued, otherwise it queues it there.
 *
 * Thus it is possible to receive the wakeup prior to going to sleep and
 * the race conditions are covered.
 */
static inline void
_tsleep_interlock(int gd, const volatile void *ident, int flags)
{
	panic("_tsleep_interlock");
/*
	thread_t td = gd->gd_curthread;
	int id;

	crit_enter_quick(td);
	if (td->td_flags & TDF_TSLEEPQ) {
		id = LOOKUP(td->td_wchan);
		TAILQ_REMOVE(&gd->gd_tsleep_hash[id], td, td_sleepq);
		if (TAILQ_FIRST(&gd->gd_tsleep_hash[id]) == NULL) {
			atomic_clear_cpumask(&slpque_cpumasks[id],
					     gd->gd_cpumask);
		}
	} else {
		td->td_flags |= TDF_TSLEEPQ;
	}
	id = LOOKUP(ident);
	TAILQ_INSERT_TAIL(&gd->gd_tsleep_hash[id], td, td_sleepq);
	atomic_set_cpumask(&slpque_cpumasks[id], gd->gd_cpumask);
	td->td_wchan = ident;
	td->td_wdomain = flags & PDOMAIN_MASK;
	crit_exit_quick(td);
*/
}

void
tsleep_interlock(const volatile void *ident, int flags)
{
    /* globaldata_t */ int mycpu;
	_tsleep_interlock(mycpu, ident, flags);
}

/* from kern/vfs_bio.c */

/*
 * Hold a buffer, preventing it from being reused.  This will prevent
 * normal B_RELBUF operations on the buffer but will not prevent B_INVAL
 * operations.  If a B_INVAL operation occurs the buffer will remain held
 * but the underlying pages may get ripped out.
 *
 * These functions are typically used in VOP_READ/VOP_WRITE functions
 * to hold a buffer during a copyin or copyout, preventing deadlocks
 * or recursive lock panics when read()/write() is used over mmap()'d
 * space.
 *
 * NOTE: bqhold() requires that the buffer be locked at the time of the
 *	 hold.  bqdrop() has no requirements other than the buffer having
 *	 previously been held.
 */
void
bqhold(struct buf *bp)
{
	atomic_add_int(1, &bp->b_refs);
}

/*
 * waitrunningbufspace()
 *
 * If runningbufspace exceeds 4/6 hirunningspace we block until
 * runningbufspace drops to 3/6 hirunningspace.  We also block if another
 * thread blocked here in order to be fair, even if runningbufspace
 * is now lower than the limit.
 *
 * The caller may be using this function to block in a tight loop, we
 * must block while runningbufspace is greater than at least
 * hirunningspace * 3 / 6.
 */
void
waitrunningbufspace(void)
{
	panic("waitrunningbufspace");
/*
	long limit = hirunningspace * 4 / 6;

	if (runningbufspace > limit || runningbufreq) {
		spin_lock(&bufcspin);
		while (runningbufspace > limit || runningbufreq) {
			runningbufreq = 1;
			ssleep(&runningbufreq, &bufcspin, 0, "wdrn1", 0);
		}
		spin_unlock(&bufcspin);
	}
*/
}

/*
 *
 * Get a lock sleeping non-interruptably until it becomes available.
 *
 * XXX lk_wmesg can race, but should not result in any operational issues.
 */
/*
static inline int
BUF_LOCK(struct buf *bp, int locktype)
{
	bp->b_lock.lk_wmesg = buf_wmesg;
	return (lockmgr(&(bp)->b_lock, locktype));
}
*/

/*
 * findblk:
 *
 *      Locate and return the specified buffer.  Unless flagged otherwise,
 *      a locked buffer will be returned if it exists or NULL if it does not.
 *
 *      findblk()'d buffers are still on the bufqueues and if you intend
 *      to use your (locked NON-TEST) buffer you need to bremfree(bp)
 *      and possibly do other stuff to it.
 *
 *      FINDBLK_TEST    - Do not lock the buffer.  The caller is responsible
 *                        for locking the buffer and ensuring that it remains
 *                        the desired buffer after locking.
 *
 *      FINDBLK_NBLOCK  - Lock the buffer non-blocking.  If we are unable
 *                        to acquire the lock we return NULL, even if the
 *                        buffer exists.
 *
 *      FINDBLK_REF     - Returns the buffer ref'd, which prevents normal
 *                        reuse by getnewbuf() but does not prevent
 *                        disassociation (B_INVAL).  Used to avoid deadlocks
 *                        against random (vp,loffset)s due to reassignment.
 *
 *      (0)             - Lock the buffer blocking.
 *
 * MPSAFE
 */
struct buf *
findblk(struct vnode *vp, off_t loffset, int flags)
{
        struct buf *bp;
        int lkflags;

        lkflags = LK_EXCLUSIVE;
        if (flags & FINDBLK_NBLOCK)
                lkflags |= LK_NOWAIT;

        for (;;) {
                /*
                 * Lookup.  Ref the buf while holding v_token to prevent
                 * reuse (but does not prevent diassociation).
                 */
                lwkt_gettoken_shared(&vp->v_token);
                /* XXX bp = buf_rb_hash_RB_LOOKUP(&vp->v_rbhash_tree, loffset); */
                if (bp == NULL) {
                        lwkt_reltoken(&vp->v_token);
                        return(NULL);
                }
                bqhold(bp);
                lwkt_reltoken(&vp->v_token);

                /*
                 * If testing only break and return bp, do not lock.
                 */
                if (flags & FINDBLK_TEST)
                        break;

                /*
                 * Lock the buffer, return an error if the lock fails.
                 * (only FINDBLK_NBLOCK can cause the lock to fail).
                 */
/*XXX
                if (BUF_LOCK(bp, lkflags)) {
                        atomic_subtract_int(1, &bp->b_refs);
                        
                        return(NULL);
                } */

                /*
                 * Revalidate the locked buf before allowing it to be
                 * returned.
                 */
                if (bp->b_vp == vp /* XX && bp->b_loffset == loffset */)
                        break;
                atomic_subtract_int( 1, &bp->b_refs);
                /* XXX BUF_UNLOCK(bp); */
        }

        /*
         * Success
         */
        if ((flags & FINDBLK_REF) == 0)
                atomic_subtract_int( 1, &bp->b_refs);
        return(bp);
}

int hidirtybufspace;

int bread( struct vnode *devvp /*struct super_block *sb*/, off_t loffset, int size, struct buf **bpp)
{
	struct buffer_head *bh;
	unsigned i, num;
	sector_t block;
	int error;

	BUG_ON(size % BLOCK_SIZE);
		/* size must be multiple of BLOCK_SIZE */
	BUG_ON(loffset % BLOCK_SIZE);
		/* loffset must be multiple of BLOCK_SIZE */

	*bpp = kzalloc(sizeof(**bpp), GFP_KERNEL);
	if (!(*bpp)) {
		error = -ENOMEM;
		goto failed;
	}

	(*bpp)->b_data = kzalloc(size, GFP_KERNEL);
	if (!(*bpp)->b_data) {
		error = -ENOMEM;
		goto failed;
	}

	num = size / BLOCK_SIZE;
	block = loffset / BLOCK_SIZE;

	for (i = 0; i < num; ++i) {
		bh = sb_bread(devvp->sb, block + i);
		if (!bh) {
			error = -ENOMEM;
			goto failed;
		}
		memcpy(((*bpp)->b_data + i*BLOCK_SIZE), bh->b_data, BLOCK_SIZE);
		brelse(bh);
	}

	return 0;
failed:
	return error;
}

/*
 * bwrite:
 *
 *	Synchronous write, waits for completion.
 *
 *	Write, release buffer on completion.  (Done by iodone
 *	if async).  Do not bother writing anything if the buffer
 *	is invalid.
 *
 *	Note that we set B_CACHE here, indicating that buffer is
 *	fully valid and thus cacheable.  This is true even of NFS
 *	now so we set it generally.  This could be set either here 
 *	or in biodone() since the I/O is synchronous.  We put it
 *	here.
 */
int
bwrite(struct buf *bp)
{
	panic("bwrite");
/*
	int error;

	if (bp->b_flags & B_INVAL) {
		brelse(bp);
		return (0);
	}
	if (BUF_REFCNTNB(bp) == 0)
		panic("bwrite: buffer is not busy???");

	* Mark the buffer clean 
	bundirty(bp);

	bp->b_flags &= ~(B_ERROR | B_EINTR);
	bp->b_flags |= B_CACHE;
	bp->b_cmd = BUF_CMD_WRITE;
	bp->b_bio1.bio_done = biodone_sync;
	bp->b_bio1.bio_flags |= BIO_SYNC;
	vfs_busy_pages(bp->b_vp, bp);

	
	 * Normal bwrites pipeline writes.  NOTE: b_bufsize is only
	 * valid for vnode-backed buffers.
	
	bsetrunningbufspace(bp, bp->b_bufsize);
	vn_strategy(bp->b_vp, &bp->b_bio1);
	error = biowait(&bp->b_bio1, "biows");
	brelse(bp);

	return (error);
*/
}

#ifndef _LINUX_BUFFER_HEAD_H
#undef brelse
void
brelse(struct buf *bp)
{
	panic("brelse");
}
#endif

int bd_heatup(void)
{
	panic("bd_heatup");
	return 0;
}

/* from kern/vfs_mount.c */
int vmntvnodescan(
	struct mount *mp,
	int flags,
	int (*fastfunc)(struct mount *mp, struct vnode *vp, void *data),
	int (*slowfunc)(struct mount *mp, struct vnode *vp, void *data),
	void *data
) {
	panic("vmntvnodescan");
	return 0;
}

/* from kern/kern_slaballoc.c */
#undef kfree
void dfly_kfree(void *ptr, struct malloc_type *type)
{
	kfree(ptr);
}

void dfly_brelse(struct buf *bp)
{
	kfree(bp->b_data);
	kfree(bp);
}

#undef kmalloc
void *dfly_kmalloc(unsigned long size, struct malloc_type *type, int flags)
{
	return kzalloc(size, GFP_KERNEL);
}

MALLOC_DEFINE(M_TEMP, "temp", "misc temporary data buffers");

/* from kern/kern_synch.c */
/* int
tsleep(const volatile void *ident, int flags, const char *wmesg, int timo)*/

int
tsleep(const volatile void *ident, int flags, const char *wmesg, int timo)
{
    /* panic("tsleep"); */
	return 0;
}

void wakeup(const volatile void *ident)
{
	panic("wakeup");
}

/* from kern/clock.c */
time_t time_second;             /* read-only 'passive' uptime in seconds */

void getmicrotime(struct timeval *tvp)
{
	do_gettimeofday(tvp);
}

/* from sys/signal2.h */
int __cursig(struct lwp *lp, int mayblock, int maytrace)
{
	panic("__cursig");
	return 0;
}

/* from kern/lwkt_thread.c */
int lwkt_create(void (*func)(void *), void *arg,
	struct thread **tdp, thread_t template, int tdflags, int cpu,
	const char *fmt, ...)
{
	panic("lwkt_create");
	return 0;
}

void lwkt_exit(void)
{
	panic("lwkt_exit");
}

/* from kern/subr_param.c */
int hz;

/* from kern/kern_iosched.c */
void bwillwrite(int bytes)
{
	panic("bwillwrite");
}

/* from kern/kern_prot.c */
int priv_check_cred(struct ucred *cred, int priv, int flags)
{
	panic("priv_check_cred");
	return 0;
}

/* from kern/subr_prf.c */
int kvprintf(const char *fmt, __va_list ap)
{
	panic("kvprintf");
	return 0;
}

void
vput(struct vnode *vp)
{
	panic("vput");
/*         vn_unlock(vp);
         vrele(vp); */
}

/*
 * BIO tracking structure - tracks in-progress BIOs
 */
struct bio_track {
	int     bk_active;      /* I/O's currently in progress */
};

/*
 * runningbufwakeup:
 *
 *	Accounting for I/O in progress.
 *
 */
static inline void
runningbufwakeup(struct buf *bp)
{
	panic("runningbufwakeup");
/*
	long totalspace;
	long limit;

	if ((totalspace = bp->b_runningbufspace) != 0) {
		spin_lock(&bufcspin);
		runningbufspace -= totalspace;
		--runningbufcount;
		bp->b_runningbufspace = 0;

		 * see waitrunningbufspace() for limit test.

		limit = hirunningspace * 3 / 6;
		if (runningbufreq && runningbufspace <= limit) {
			runningbufreq = 0;
			spin_unlock(&bufcspin);
			wakeup(&runningbufreq);
		} else {
			spin_unlock(&bufcspin);
		}
		bd_signal(totalspace);
	}
*/
}

/*
 * bqrelse:
 *
 *	Release a buffer back to the appropriate queue but do not try to free
 *	it.  The buffer is expected to be used again soon.
 *
 *	bqrelse() is used by bdwrite() to requeue a delayed write, and used by
 *	biodone() to requeue an async I/O on completion.  It is also used when
 *	known good buffers need to be requeued but we think we may need the data
 *	again soon.
 *
 *	XXX we should be able to leave the B_RELBUF hint set on completion.
 *
 * MPSAFE
 */
void
bqrelse(struct buf *bp)
{
	panic("bqrelse");
}

/*
 * bpdone:
 *
 *	Finish I/O on a buffer after all BIOs have been processed.
 *	Called when the bio chain is exhausted or by biowait.  If called
 *	by biowait, elseit is typically 0.
 *
 *	bpdone is also responsible for setting B_CACHE in a B_VMIO bp.
 *	In a non-VMIO bp, B_CACHE will be set on the next getblk() 
 *	assuming B_INVAL is clear.
 *
 *	For the VMIO case, we set B_CACHE if the op was a read and no
 *	read error occured, or if the op was a write.  B_CACHE is never
 *	set if the buffer is invalid or otherwise uncacheable.
 *
 *	bpdone does not mess with B_INVAL, allowing the I/O routine or the
 *	initiator to leave B_INVAL set to brelse the buffer out of existance
 *	in the biodone routine.
 */
void
bpdone(struct buf *bp, int elseit)
{
	panic("bpdone");
}

/*
 * Normal biodone.
 */
void biodone(struct bio *bio)
{
	struct buf *bp;
 	panic("biodone");

	/*
     * Run up the chain of BIO's.   Leave b_cmd intact for the duration.
     */
/*
    struct buf *bp = bio->bio_buf;
 	runningbufwakeup(bp);
          while (bio) {
                  biodone_t *done_func;
                  struct bio_track *track;
  
                  *
                   * BIO tracking.  Most but not all BIOs are tracked.
                   *
                  if ((track = bio->bio_track) != NULL) {
                          bio_track_rel(track);
                          bio->bio_track = NULL;
                  }
  
                  *
                   * A bio_done function terminates the loop.  The function
                   * will be responsible for any further chaining and or
                   * buffer management.
                   *
                   * WARNING!  The done function can deallocate the buffer!
                   *
                  if ((done_func = bio->bio_done) != NULL) {
                          bio->bio_done = NULL;
                          done_func(bio);
                          return;
                  }
                  bio = bio->bio_prev;
          }
  */
          /*
          * If we've run out of bio's do normal [a]synchronous completion.
          */
         bpdone(bp, 1);
 }

/*
 * Push another BIO layer onto an existing BIO and return it.  The new
 * BIO layer may already exist, holding cached translation data.
 */
struct bio *push_bio(struct bio *bio)
{
        struct bio *nbio;
	panic("push_bio");
/*
        if ((nbio = bio->bio_next) == NULL) {
                int index = bio - &bio->bio_buf->b_bio_array[0];
                if (index >= NBUF_BIO - 1) {
                        panic("push_bio: too many layers bp %p",
                                bio->bio_buf);
                }

                nbio = &bio->bio_buf->b_bio_array[index + 1];
                bio->bio_next = nbio;
                nbio->bio_prev = bio;
                nbio->bio_buf = bio->bio_buf;
                nbio->bio_offset = NOOFFSET;
                nbio->bio_done = NULL;
                nbio->bio_next = NULL;
        } */
        /* KKASSERT(nbio->bio_done == NULL); */
        return(nbio);
}

/*
 * Pop a BIO translation layer, returning the previous layer.  The
 * must have been previously pushed.
 */
struct bio *
pop_bio(struct bio *bio)
{
	panic("pop_bio");
	/* return(bio->bio_prev); */
}

/*
 * regetblk(bp)
 *
 * Reacquire a buffer that was previously released to the locked queue,
 * or reacquire a buffer which is interlocked by having bioops->io_deallocate
 * set B_LOCKED (which handles the acquisition race).
 *
 * To this end, either B_LOCKED must be set or the dependancy list must be
 * non-empty.
 *
 * MPSAFE
 */
void
regetblk(struct buf *bp)
{
	panic("regetblk");
	/* KKASSERT((bp->b_flags & B_LOCKED) || LIST_FIRST(&bp->b_dep) != NULL); 
	BUF_LOCK(bp, LK_EXCLUSIVE | LK_RETRY); */
	kfree(bp); 
}

struct buf *getblk (struct vnode *vp, off_t loffset, int size, int blkflags, int slptimeo) 
{
	panic("getblk");
}

/*
 * geteblk:
 *
 *	Get an empty, disassociated buffer of given size.  The buffer is
 *	initially set to B_INVAL.
 *
 *	critical section protection is not required for the allocbuf()
 *	call because races are impossible here.
 *
 * MPALMOSTSAFE
 */
struct buf *geteblk(int size)
{
	panic("geteblk");
	
/*
	struct buf *bp;
	int maxsize;

	maxsize = (size + BKVAMASK) & ~BKVAMASK;

	while ((bp = getnewbuf(0, 0, size, maxsize)) == NULL)
		;
	allocbuf(bp, size); */
	//bp->b_flags |= B_INVAL;	/* b_dep cleared by getnewbuf() */
	//KKASSERT(dsched_is_clear_buf_priv(bp));
	//return (bp);
}

void
bcopy(const void *src, void *dst, size_t len)
{
	const char *s = src;
	char *d = dst;

	while (len-- != 0)
		*d++ = *s++;
}

/*
 * vfs_bio_clrbuf:
 *
 *	Clear a buffer.  This routine essentially fakes an I/O, so we need
 *	to clear B_ERROR and B_INVAL.
 *
 *	Note that while we only theoretically need to clear through b_bcount,
 *	we go ahead and clear through b_bufsize.
 */

void
vfs_bio_clrbuf(struct buf *bp)
{
	panic("vfs_bio_clrbuf");
/*
	int i, mask = 0;
	caddr_t sa, ea;
	if ((bp->b_flags & (B_VMIO | B_MALLOC)) == B_VMIO) {
		bp->b_flags &= ~(B_INVAL | B_EINTR | B_ERROR);
		if ((bp->b_xio.xio_npages == 1) && (bp->b_bufsize < PAGE_SIZE) &&
		    (bp->b_loffset & PAGE_MASK) == 0) {
			mask = (1 << (bp->b_bufsize / DEV_BSIZE)) - 1;
			if ((bp->b_xio.xio_pages[0]->valid & mask) == mask) {
				bp->b_resid = 0;
				return;
			}
			if (((bp->b_xio.xio_pages[0]->flags & PG_ZERO) == 0) &&
			    ((bp->b_xio.xio_pages[0]->valid & mask) == 0)) {
				bzero(bp->b_data, bp->b_bufsize);
				bp->b_xio.xio_pages[0]->valid |= mask;
				bp->b_resid = 0;
				return;
			}
		}
		sa = bp->b_data;
		for(i=0;i<bp->b_xio.xio_npages;i++,sa=ea) {
			int j = ((vm_offset_t)sa & PAGE_MASK) / DEV_BSIZE;
			ea = (caddr_t)trunc_page((vm_offset_t)sa + PAGE_SIZE);
			ea = (caddr_t)(vm_offset_t)ulmin(
			    (u_long)(vm_offset_t)ea,
			    (u_long)(vm_offset_t)bp->b_data + bp->b_bufsize);
			mask = ((1 << ((ea - sa) / DEV_BSIZE)) - 1) << j;
			if ((bp->b_xio.xio_pages[i]->valid & mask) == mask)
				continue;
			if ((bp->b_xio.xio_pages[i]->valid & mask) == 0) {
				if ((bp->b_xio.xio_pages[i]->flags & PG_ZERO) == 0) {
					bzero(sa, ea - sa);
				}
			} else {
				for (; sa < ea; sa += DEV_BSIZE, j++) {
					if (((bp->b_xio.xio_pages[i]->flags & PG_ZERO) == 0) &&
						(bp->b_xio.xio_pages[i]->valid & (1<<j)) == 0)
						bzero(sa, DEV_BSIZE);
				}
			}
			bp->b_xio.xio_pages[i]->valid |= mask;
			vm_page_flag_clear(bp->b_xio.xio_pages[i], PG_ZERO);
		}
		bp->b_resid = 0;
	} else {
		clrbuf(bp);
	}
*/
}

/*
 * Adjust buffer cache buffer's activity count.  This
 * works similarly to vm_page->act_count.
 */
void
buf_act_advance(struct buf *bp)
{
	panic("buf_act_advance");
/*
	if (bp->b_act_count > ACT_MAX - ACT_ADVANCE)
		bp->b_act_count = ACT_MAX;
	else
		bp->b_act_count += ACT_ADVANCE;
*/
}

/*
 * bremfree:
 *
 *	Remove the buffer from the appropriate free list.
 */
static inline void
_bremfree(struct buf *bp)
{
	panic("_bremfree");
/*
	if (bp->b_qindex != BQUEUE_NONE) {
		KASSERT(BUF_REFCNTNB(bp) == 1, 
				("bremfree: bp %p not locked",bp));
		TAILQ_REMOVE(&bufqueues[bp->b_qindex], bp, b_freelist);
		bp->b_qindex = BQUEUE_NONE;
	} else {
		if (BUF_REFCNTNB(bp) <= 1)
			panic("bremfree: removing a buffer not on a queue");
	}
*/
}

void
bremfree(struct buf *bp)
{
	//spin_lock(&bufqspin);
	_bremfree(bp);
	//spin_unlock(&bufqspin);
}

/*
 * bdwrite:
 *
 *	Delayed write. (Buffer is marked dirty).  Do not bother writing
 *	anything if the buffer is marked invalid.
 *
 *	Note that since the buffer must be completely valid, we can safely
 *	set B_CACHE.  In fact, we have to set B_CACHE here rather then in
 *	biodone() in order to prevent getblk from writing the buffer
 *	out synchronously.
 */
void
bdwrite(struct buf *bp)
{
	panic("bdwrite");

	/*
	 * note: we cannot initiate I/O from a bdwrite even if we wanted to,
	 * due to the softdep code.
	 */
}

/*
 * This is the clustered version of bawrite().  It works similarly to
 * cluster_write() except I/O on the buffer is guaranteed to occur.
 */
int
cluster_awrite(struct buf *bp)
{
	panic("cluser_awrite");
}

/*
 * Initiate I/O on a vnode.
 *
 * SWAPCACHE OPERATION:
 *
 *	Real buffer cache buffers have a non-NULL bp->b_vp.  Unfortunately
 *	devfs also uses b_vp for fake buffers so we also have to check
 *	that B_PAGING is 0.  In this case the passed 'vp' is probably the
 *	underlying block device.  The swap assignments are related to the
 *	buffer cache buffer's b_vp, not the passed vp.
 *
 *	The passed vp == bp->b_vp only in the case where the strategy call
 *	is made on the vp itself for its own buffers (a regular file or
 *	block device vp).  The filesystem usually then re-calls vn_strategy()
 *	after translating the request to an underlying device.
 *
 *	Cluster buffers set B_CLUSTER and the passed vp is the vp of the
 *	underlying buffer cache buffers.
 *
 *	We can only deal with page-aligned buffers at the moment, because
 *	we can't tell what the real dirty state for pages straddling a buffer
 *	are.
 *
 *	In order to call swap_pager_strategy() we must provide the VM object
 *	and base offset for the underlying buffer cache pages so it can find
 *	the swap blocks.
 */
void
vn_strategy(struct vnode *vp, struct bio *bio)
{
	panic("vn_strategy");
}

/*
 * This version of bread issues any required I/O asyncnronously and
 * makes a callback on completion.
 *
 * The callback must check whether BIO_DONE is set in the bio and issue
 * the bpdone(bp, 0) if it isn't.  The callback is responsible for clearing
 * BIO_DONE and disposing of the I/O (bqrelse()ing it).
 */
void
breadcb(struct vnode *vp, off_t loffset, int size,
	void (*func)(struct bio *), void *arg)
{
	panic("breadcb");
}

/*
 * Simple call that a filesystem can make to try to get rid of a
 * vnode.  It will fail if anyone is referencing the vnode (including
 * the caller).
 *
 * The filesystem can check whether its in-memory inode structure still
 * references the vp on return.
 */
void
vclean_unlocked(struct vnode *vp)
{
	panic("vclean_unlocked");
/*
	vx_get(vp);
	if (sysref_isactive(&vp->v_sysref) == 0)
		vgone_vxlocked(vp);
	vx_put(vp);
*/
}

/*
 * Return TRUE if we are under our severe low-free-pages threshold
 *
 * This causes user processes to stall to avoid exhausting memory that
 * the kernel might need.
 *
 * reserved < severe < minimum < target < paging_target
 */
int
vm_page_count_severe(void)
{
		panic("vm_page_count_severe");
}

/****************************************************************
 *			VNODE ACQUISITION FUNCTIONS		*
 ****************************************************************
 *
 * These functions must be used when accessing a vnode via an auxiliary
 * reference such as the namecache or free list, or when you wish to
 * do a combo ref+lock sequence.
 *
 * These functions are MANDATORY for any code chain accessing a vnode
 * whos activation state is not known.
 *
 * vget() can be called with LK_NOWAIT and will return EBUSY if the
 * lock cannot be immediately acquired.
 *
 * vget()/vput() are used when reactivation is desired.
 *
 * vx_get() and vx_put() are used when reactivation is not desired.
 */
int
vget(struct vnode *vp, int flags)
{
	panic("vget");

}

/*
 * Remove an auxiliary reference from the vnode.
 *
 * vdrop needs to check for a VCACHE->VFREE transition to catch cases
 * where a vnode is held past its reclamation.  We use v_spin to
 * interlock VCACHED -> !VCACHED transitions.
 *
 * MPSAFE
 */
void
vdrop(struct vnode *vp)
{
	panic("vdrop");
}

int	nvtruncbuf (struct vnode *vp, off_t length, int blksize, int boff,int trivial)
{
	panic("nvtruncbuf");
}

/*
 * Allocate a new vnode and associate it with a tag, mount point, and
 * operations vector.
 *
 * A VX locked and refd vnode is returned.  The caller should setup the
 * remaining fields and vx_put() or, if he wishes to leave a vref,
 * vx_unlock() the vnode.
 */
int
getnewvnode(enum vtagtype tag, struct mount *mp, struct vnode **vpp, int lktimeout, int lkflags)
{
	panic("gennewvnode");

	return (0);
}

/*
 * Relase a VX lock that also held a ref on the vnode.
 *
 * vx_put needs to check for a VCACHED->VFREE transition to catch the
 * case where e.g. vnlru issues a vgone*().
 *
 * MPSAFE
 */
void
vx_put(struct vnode *vp)
{
	panic("vx_put");
}

/*
 * Add a vnode to the alias list hung off the cdev_t.  We only associate
 * the device number with the vnode.  The actual device is not associated
 * until the vnode is opened (usually in spec_open()), and will be 
 * disassociated on last close.
 */
void
addaliasu(struct vnode *nvp, int x, int y)
{
	panic("addaliasu");
}

static inline
void
_vsetflags(struct vnode *vp, int flags)
{
	panic("_vsetflags");
	//atomic_set_int(&vp->v_flag, flags);
}

void
vsetflags(struct vnode *vp, int flags)
{
	_vsetflags(vp, flags);
}

/*
 * Initialize VMIO for a vnode.  This routine MUST be called before a
 * VFS can issue buffer cache ops on a vnode.  It is typically called
 * when a vnode is initialized from its inode.
 */
int
vinitvmio(struct vnode *vp, off_t filesize, int blksize, int boff)
{
	panic("vinitvmio");
}

void
vhold_interlocked(struct vnode *vp)
{
	panic("vhold_interlocked");
	//atomic_add_int(&vp->v_auxrefs, 1);
}

/*
 * This helper function may be used by VFSs to implement UNIX initial
 * ownership semantics when creating new objects inside directories.
 */
uid_t vop_helper_create_uid(struct mount *mp, mode_t dmode, uid_t duid,struct ucred *cred, unsigned short *modep)
{
	panic("vop_helper_create_uid");
/*
#ifdef SUIDDIR
	if ((mp->mnt_flag & MNT_SUIDDIR) && (dmode & S_ISUID) &&
	    duid != cred->cr_uid && duid) {
		*modep &= ~07111;
		return(duid);
	}
#endif
	return(cred->cr_uid);
*/
}

/*
 * This yield is designed for kernel threads with a user context.
 *
 * The kernel acting on behalf of the user is potentially cpu-bound,
 * this function will efficiently allow other threads to run and also
 * switch to other processes by releasing.
 *
 * The lwkt_user_yield() function is designed to have very low overhead
 * if no yield is determined to be needed.
 */
void
lwkt_user_yield(void)
{
	panic("lwkt_user_yield");
}

/*
 * Calculate the total number of references to a special device.  This
 * routine may only be called for VBLK and VCHR vnodes since v_rdev is
 * an overloaded field.  Since udev2dev can now return NULL, we have
 * to check for a NULL v_rdev.
 */
int
count_dev( unsigned long long  dev)
{
	panic("count_dev");
/*
        int count = 0;
        struct vnode *vp;
        if (SLIST_FIRST(&dev->si_hlist)) {
                lwkt_gettoken(&spechash_token);
                SLIST_FOREACH(vp, &dev->si_hlist, v_cdevnext) {
                        count += vp->v_opencount;
                }
                lwkt_reltoken(&spechash_token);
        }
        return(count);
*/

}

int
vcount(struct vnode *vp)
{
	panic("vcount");
/*
	if (vp->v_rdev == NULL)
		return(0);
	return(count_dev(vp->v_rdev));
*/
}

int
vm_page_count_min(int donotcount)
{
	panic("vm_page_count_min");
/*
    return (vmstats.v_free_min + donotcount >
	    (vmstats.v_free_count + vmstats.v_cache_count) ||
	    vmstats.v_free_reserved > vmstats.v_free_count);
*/
}

/*
static void
bremfree_locked(struct buf *bp)
{
	_bremfree(bp);
}
*/

