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

/**
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v.
 */
/* static inline */ void atomic_add_long(int v, long i)
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

static inline void
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

int bread(struct super_block *sb, off_t loffset, int size, struct buf **bpp)
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
		bh = sb_bread(sb, block + i);
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

#ifndef _LINUX_BUFFER_HEAD_H
void brelse(struct buf *bp)
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
int tsleep(void *ident, int flags, const char *wmesg, int timo)
{
    /* panic("tsleep"); */
	return 0;
}

void wakeup(void *ident)
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
