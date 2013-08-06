#ifndef _DFLY_WRAP_H
#define _DFLY_WRAP_H

/*
 * Header file providing compability "glue" between
 * DragonFly BSD and Linux: Contains mostly dummy
 * definitions and no-op functions.
 *
 * Use as follows: First include linux headers, then
 * dfly_wrap.h, then dfly headers.
 */

#include <linux/types.h>  // for u_ont32_t, uint64_t
#include <asm/bug.h>      // for BUG_ON
#include <linux/time.h>   // for struct timespec
#include <linux/bio.h>    // for struct bio
#include <linux/kernel.h> // for printk, simple_strtoul
#include <linux/ctype.h>  // for isascii, isdigit, isalpha, isupper, isspace
#include <linux/slab.h>   // for kmalloc
#include <linux/string.h> // for memcmp, memcpy, memset
#include <linux/buffer_head.h> // for brelse
#include "dfly/sys/queue.h"

#ifndef _SYS_UUID_H_
#include "dfly/sys/uuid.h"
#endif


/*
 * required DragonFly BSD definitions
 */

// indicate we are in kernel
#define _KERNEL 1

#define atomic_add_ptr(p, v) \
	atomic_add_long((volatile u_long *)(p), (u_long)(v))
#define atomic_add_acq_ptr(p, v) \
	atomic_add_acq_long((volatile u_long *)(p), (u_long)(v))
#define atomic_add_rel_ptr(p, v) \
	atomic_add_rel_long((volatile u_long *)(p), (u_long)(v))
//#define atomic_add_int(p, v)		atomic_add(p, v)
#define atomic_add_int                  atomic_add
#define atomic_subtract_int		atomic_sub
#define	atomic_add_acq_int		atomic_add_int
#define	atomic_add_rel_int		atomic_add_int
#define	atomic_subtract_32	atomic_subtract_int

// from sys/cdefs.h
#define __unused
#define MAXCPUFIFO      32	/* power of 2 */
#define MAXCPUFIFO_MASK	(MAXCPUFIFO - 1)
#define LWKT_MAXTOKENS	32	/* max tokens beneficially held by thread */
#define td_toks_end		td_toks_array[LWKT_MAXTOKENS]
#define td_toks_base		td_toks_array[0]

// from sys/dirent.h
#define DT_DBF	15		/* database record file*/

// from sys/stat.h
#define S_IFDB	0110000		/* record access file */
#define UF_NOHISTORY    0x00000040      /* do not retain history/snapshots */
#define SF_NOHISTORY    0x00400000      /* do not retain history/snapshots */

// from cpu/i386/include/param.h
#define SMP_MAXCPU      16

// from sys/malloc.h
struct malloc_type {
    struct malloc_type *ks_next;    /* next in list */
    long    ks_memuse[SMP_MAXCPU];  /* total memory held in bytes */
    long    ks_loosememuse;         /* (inaccurate) aggregate memuse */
    long    ks_limit;       /* most that are allowed to exist */
    long    ks_size;        /* sizes of this thing that are allocated */
    long    ks_inuse[SMP_MAXCPU]; /* # of allocs currently in use */
    int64_t ks_calls;     /* total packets of this type ever allocated */
    long    ks_maxused;     /* maximum number ever used */
    uint32_t ks_magic;    /* if it's not magic, don't touch it */
    const char *ks_shortdesc;       /* short description */
    uint16_t ks_limblocks; /* number of times blocked for hitting limit */
    uint16_t ks_mapblocks; /* number of times blocked for kernel map */
    long    ks_reserved[4]; /* future use (module compatibility) */
};

#define M_MAGIC         877983977       /* time when first defined :-) */
#define MALLOC_DECLARE(type) \
    extern struct malloc_type type[1]
#define MALLOC_DEFINE(type, shortdesc, longdesc)        \
    struct malloc_type type[1] = {                  \
        { NULL, { 0 }, 0, 0, 0, { 0 }, 0, 0, M_MAGIC, shortdesc, 0, 0 } \
    };
#define M_WAITOK        0x0002  /* wait for resources / alloc from cache */
#define M_ZERO          0x0100  /* bzero() the allocation */
#define M_USE_RESERVE   0x0200  /* can eat into free list reserve */

#define kfree(addr, type) dfly_kfree(addr, type)
#define kmalloc(size, type, flags) dfly_kmalloc(size, type, flags)

MALLOC_DECLARE(M_TEMP);

void dfly_kfree (void *addr, struct malloc_type *type);
void *dfly_kmalloc (unsigned long size, struct malloc_type *type, int flags);

// from sys/ktr.h
#define KTR_INFO_MASTER_EXTERN(master)

// from sys/proc.h
#define PRISON_ROOT     0x1
#define TOK_EXCLUSIVE	0x00000001	/* Exclusive lock held */
#define TOK_EXCLREQ	0x00000002	/* Exclusive request pending */
#define TOK_INCR	4		/* Shared count increment */
#define TOK_COUNTMASK	(~(long)(TOK_EXCLUSIVE|TOK_EXCLREQ))

#define TOKEN_STRING	"REF=%p TOK=%p TD=%p"
#define TOKEN_ARGS	lwkt_tokref_t ref, lwkt_token_t tok, struct thread *td
#define CONTENDED_STRING	TOKEN_STRING " (contention started)"
#define UNCONTENDED_STRING	TOKEN_STRING " (contention stopped)"
#if !defined(KTR_TOKENS)
#define	KTR_TOKENS	KTR_ALL
#endif

#if 0
KTR_INFO(KTR_TOKENS, tokens, release, 2, TOKEN_STRING, TOKEN_ARGS);
KTR_INFO(KTR_TOKENS, tokens, remote, 3, TOKEN_STRING, TOKEN_ARGS);
KTR_INFO(KTR_TOKENS, tokens, reqremote, 4, TOKEN_STRING, TOKEN_ARGS);
KTR_INFO(KTR_TOKENS, tokens, reqfail, 5, TOKEN_STRING, TOKEN_ARGS);
KTR_INFO(KTR_TOKENS, tokens, drain, 6, TOKEN_STRING, TOKEN_ARGS);
KTR_INFO(KTR_TOKENS, tokens, contention_start, 7, CONTENDED_STRING, TOKEN_ARGS);
KTR_INFO(KTR_TOKENS, tokens, contention_stop, 7, UNCONTENDED_STRING, TOKEN_ARGS);
#endif

#define logtoken(name, ref)						\
	KTR_LOG(tokens_ ## name, ref, ref->tr_tok, curthread)
struct lwp {};

// from sys/thread.h
typedef struct lwkt_token       *lwkt_token_t;
typedef struct lwkt_tokref      *lwkt_tokref_t;

struct lwkt_tokref {
    lwkt_token_t        tr_tok;         /* token in question */
    long                tr_count;       /* TOK_EXCLUSIVE|TOK_EXCLREQ or 0 */
    struct thread       *tr_owner;      /* me */
};

typedef struct lwkt_token {
    long                t_count;        /* Shared/exclreq/exclusive access */
    struct lwkt_tokref  *t_ref;         /* Exclusive ref */
    long                t_collisions;   /* Collision counter */
    const char          *t_desc;        /* Descriptive name */
} lwkt_token;


#define crit_enter()
#define crit_exit()

struct thread {
    struct lwp  *td_lwp;        /* (optional) associated lwp */
    lwkt_tokref_t td_toks_stop;		/* tokens we want */
    struct lwkt_tokref td_toks_array[LWKT_MAXTOKENS];
	struct proc	*td_proc;	/* (optional) associated process */
};
typedef struct thread *thread_t;

extern int  lwkt_create (void (*func)(void *), void *, struct thread **,
                         struct thread *, int, int, const char *, ...);
extern void lwkt_exit (void);

// from platform/pc32/include/thread.h
#define curthread   ((thread_t)NULL)

// from sys/types.h
typedef u_int32_t udev_t;         /* device number */
typedef uint64_t u_quad_t;        /* quads */

// from sys/param.h
#define MAXBSIZE        65536   /* must be power of 2 */

#define PCATCH          0x00000100      /* tsleep checks signals */

// from sys/time.h
extern time_t   time_second;

struct krate {
    int freq;
    int ticks;
    int count;
};

void getmicrotime (struct timeval *tv);

// from sys/statvfs.h
struct statvfs {
    long    f_blocks;               /* total data blocks in file system */
};

/*
 * Initialize a lock.
 */
#define BUF_LOCKINIT(bp) \
	lockinit(&(bp)->b_lock, buf_wmesg, 0, 0)

// from sys/buf.h
#define FINDBLK_TEST      0x0010  /* test only, do not lock */
#define FINDBLK_NBLOCK  0x0020  /* use non-blocking lock, can return NULL */
#define FINDBLK_REF	0x0040	/* ref the buf to prevent reuse */

#define NBUF_BIO	6

struct buf {
	off_t	b_offset;		/* Offset into file */
						/* Function to call upon completion. */
	long	b_resid;		/* Remaining I/O. */
	long	b_bufsize;		/* Allocated buffer size. */
	int	b_error;		/* Errno value. */
	long	b_flags;		/* B_* flags. */
	unsigned long    b_bcount;
    caddr_t b_data;                 /* Memory, superblocks, indirect etc. */
	atomic_t	b_refs;			/* FINDBLK_REF/bqhold()/bqdrop() */
	struct vnode *b_vp;		/* (vp, loffset) index */
	struct bio b_bio_array[NBUF_BIO]; /* BIO translation layers */ 
	struct	vnode *b_dep;		/* List of filesystem dependencies. */
};
/*
 * XXX temporary
 */
#define b_bio1		b_bio_array[0]	/* logical layer */
#define b_bio2		b_bio_array[1]	/* (typically) the disk layer */
//#define b_loffset	b_bio1.bi_io_vec.bv_offset

struct vnode;
// struct super_block *sb
int bread (struct vnode *devvp, off_t, int, struct buf **);
int bwrite(struct buf *bp);

#ifndef _LINUX_BUFFER_HEAD_H
void brelse (struct buf *);
#endif
void dfly_brelse (struct buf *);
struct buf_rb_tree {
    void    *rbh_root;
};
int     bd_heatup (void);

// from sys/mount.h
#define MNT_RDONLY      0x00000001      /* read only Filesystem */
#define MNT_WAIT        1       /* synchronously wait for I/O to complete */
#define MNT_NOWAIT      2       /* start all I/O, but do not wait for it */

struct statfs {
    long    f_blocks;               /* total data blocks in file system */
};
struct netexport {};
struct export_args {};
struct mount {
    int mnt_flag;               /* flags shared with user */
    struct statfs   mnt_stat;               /* cache of Filesystem stats */
    struct statvfs  mnt_vstat;              /* extended stats */
	struct vop_ops  *mnt_vn_spec_ops;       /* for use by the VFS */
 	struct vop_ops  *mnt_vn_fifo_ops;       /* for use by the VFS */
};

int vfs_mountedon (struct vnode *);    /* is a vfs mounted on vp */

// from sys/uio.h
enum uio_seg {
    UIO_USERSPACE,          /* from user data space */
    UIO_SYSSPACE,           /* from system space */
    UIO_NOCOPY              /* don't copy, already in object */
};

// from sys/vfscache.h
//struct vattr {};

/*
 * Vnode types.  VNON means no type or transitory type.  VINT is used
 * for internal types.  Note that VNON is skipped by the vnode scan.
 */
enum vtype	{ VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VBAD,
		  VDATABASE, VINT };
/*
 * Vnode tag types.
 * These are for the benefit of external programs only (e.g., pstat)
 * and should NEVER be inspected by the kernel.
 */
enum vtagtype	{
	VT_NON, VT_UFS, VT_NFS, VT_MFS, VT_PC, VT_LFS, VT_LOFS, VT_FDESC,
	VT_PORTAL, VT_NULL, VT_UNUSED10, VT_KERNFS, VT_PROCFS, VT_AFS,
	VT_ISOFS, VT_UNION, VT_MSDOSFS, VT_TFS, VT_VFS, VT_CODA, VT_NTFS,
	VT_HPFS, VT_NWFS, VT_SMBFS, VT_UDF, VT_EXT2FS, VT_SYNTH,
	VT_HAMMER, VT_HAMMER2, VT_DEVFS, VT_TMPFS
};
/*
 * Vnode attributes.  A field value of VNOVAL represents a field whose value
 * is unavailable (getattr) or which is not to be changed (setattr).
 *
 * Some vattr fields may be wider then what is reported to userland.
 */
struct vattr {
	enum vtype	va_type;	/* vnode type (for create) */
	u_int64_t	va_nlink;	/* number of references to file */
	u_short		va_mode;	/* files access mode and type */
	uid_t		va_uid;		/* owner user id */
	gid_t		va_gid;		/* owner group id */
	udev_t		va_fsid;	/* file system id */
	ino_t		va_fileid;	/* file id */
	u_quad_t	va_size;	/* file size in bytes */
	long		va_blocksize;	/* blocksize preferred for i/o */
	struct timespec	va_atime;	/* time of last access */
	struct timespec	va_mtime;	/* time of last modification */
	struct timespec	va_ctime;	/* time file changed */
	u_int64_t	va_gen;		/* generation number of file */
	u_long		va_flags;	/* flags defined for file */
	int		va_rmajor;	/* device the special file represents */
	int		va_rminor;
	u_quad_t	va_bytes;	/* bytes of disk space held by file */
	u_quad_t	va_filerev;	/* file modification number */
	u_int		va_vaflags;	/* operations flags, see below */
	long		va_spare;	/* remain quad aligned */
	int64_t		va_unused01;
	uuid_t		va_uid_uuid;	/* native uuids if available */
	uuid_t		va_gid_uuid;
	uuid_t		va_fsid_uuid;
};

// from sys/vfsops.h
#define VOP_OPEN(vp, mode, cred, fp)                    \
        vop_open(*(vp)->v_ops, vp, mode, cred, fp)
#define VOP_CLOSE(vp, fflag)                            \
        vop_close(*(vp)->v_ops, vp, fflag)
#define VOP_FSYNC(vp, waitfor, td)                          \
        vop_fsync(*(vp)->v_ops, vp, waitfor)
#define VOP_SETATTR(vp, vap, cred)                      \
        vop_setattr(*(vp)->v_ops, vp, vap, cred)


struct vop_inactive_args {};
//struct vop_reclaim_args {};
struct vop_reclaim_args {
	//struct vop_generic_args a_head;
    struct vnode *a_vp;
};

struct vop_ops {};
struct ucred;

int vop_open(struct vop_ops *ops, struct vnode *vp, int mode,
             struct ucred *cred, struct file *file);
int vop_setattr(struct vop_ops *ops, struct vnode *vp, struct vattr *vap, struct ucred *cred);
int vop_close(struct vop_ops *ops, struct vnode *vp, int fflag);
int vop_fsync(struct vop_ops *ops, struct vnode *vp, int waitfor);

// sys/conf.h
#define si_mountpoint   __si_u.__si_disk.__sid_mountpoint

struct cdev {
   union {
        struct {
                struct mount *__sid_mountpoint;
        } __si_disk;
   } __si_u;
};

int count_udev (int x, int y);

// from sys/vnode.h
#define VMSC_GETVP      0x01
#define VMSC_NOWAIT     0x10
#define VMSC_ONEPASS    0x20

#define V_SAVE          0x0001          /* vinvalbuf: sync file first */

#define v_umajor        v_un.vu_cdev.vu_umajor
#define v_uminor        v_un.vu_cdev.vu_uminor
#define v_rdev          v_un.vu_cdev.vu_cdevinfo

#define VINACTIVE       0x04000 /* The vnode is inactive (did VOP_INACTIVE) */

struct vnode {
    int     v_flag;                         /* vnode flags (see below) */
    void    *v_data;                        /* private data for fs */
    struct  buf_rb_tree v_rbdirty_tree;     /* RB tree of dirty bufs */
    enum    vtype v_type;                   /* vnode type */
    struct  vop_ops **v_ops;                /* vnode operations vector */
    union {
        struct {
            int vu_umajor;      /* device number for attach */
            int vu_uminor;
            struct cdev *vu_cdevinfo; /* device (VCHR, VBLK) */
        } vu_cdev;
    } v_un;
    struct  lwkt_token v_token;             /* (see above) */


    struct super_block *sb; // defined by us, we use this for sb_bread()
};

int vinvalbuf (struct vnode *vp, int save, int slpflag, int slptimeo);
int vn_isdisk (struct vnode *vp, int *errp);
int vn_lock (struct vnode *vp, int flags);
void vn_unlock (struct vnode *vp);
void vrele (struct vnode *vp);
int vmntvnodescan(struct mount *mp, int flags,
                  int (*fastfunc)(struct mount *mp, struct vnode *vp, void *data),
                  int (*slowfunc)(struct mount *mp, struct vnode *vp, void *data),
                  void *data);

// from sys/ucred.h
struct ucred {};
#define FSCRED ((struct ucred *)-1)     /* Filesystem credential */

// from sys/namecache.h
struct nchandle {};
int cache_vref(struct nchandle *, struct ucred *, struct vnode **);

// from sys/nlookup.h
#define NLC_FOLLOW              0x00000001      /* follow leaf symlink */

struct nlookupdata {
    struct nchandle nl_nch;         /* start-point and result */
    struct ucred    *nl_cred;       /* credentials for nlookup */
};

int nlookup_init(struct nlookupdata *, const char *, enum uio_seg, int);
int nlookup(struct nlookupdata *);
void nlookup_done(struct nlookupdata *);

// from cpu/*/*/stdarg.h
typedef __builtin_va_list   __va_list;  /* internally known to gcc */
#define __va_start(ap, last) \
        __builtin_va_start(ap, last)
#define __va_end(ap) \
        __builtin_va_end(ap)

// from sys/systm.h
void vput(struct vnode *vp);
struct buf *
findblk(struct vnode *vp, off_t loffset, int flags);
extern int bootverbose;         /* nonzero to print verbose messages */
#define KKASSERT(exp) BUG_ON(!(exp))
#define KASSERT(exp,msg) BUG_ON(!(exp))
#define kprintf printk
#define ksnprintf snprintf
#define strtoul simple_strtoul
//#define bcopy memcpy
#define bzero(buf, len) memset(buf, 0, len)

void bcopy(const void *src, void *dst, size_t len);
void vfs_bio_clrbuf(struct buf *bp);
void buf_act_advance(struct buf *bp);
void bqrelse(struct buf *bp);
void bremfree(struct buf *bp);
void bdwrite(struct buf *bp);
int cluster_awrite(struct buf *bp);
void vn_strategy(struct vnode *vp, struct bio *bio);
void breadcb(struct vnode *vp, off_t loffset, int size,	void (*func)(struct bio *), void *arg);
void vclean_unlocked(struct vnode *vp);
void Debugger (const char *msg);
uint32_t crc32(const void *buf, size_t size);
uint32_t crc32_ext(const void *buf, size_t size, uint32_t ocrc);
int tsleep(const volatile void *ident, int flags, const char *wmesg, int timo);
void wakeup(const volatile void *ident); //(void *ident);
int copyin (const void *udaddr, void *kaddr, size_t len);
int copyout (const void *kaddr, void *udaddr, size_t len);
u_quad_t strtouq (const char *, char **, int);
int kvprintf (const char *, __va_list);

//static inline void _tsleep_interlock(int gd, const volatile void *ident, int flags);
void tsleep_interlock (const volatile void *, int);

int atomic_cmpset_int(volatile u_int *dst, u_int exp, u_int src);
void biodone(struct bio *bio);
struct bio *push_bio(struct bio *bio);
struct bio *pop_bio(struct bio *bio);
void waitrunningbufspace(void);
void regetblk(struct buf *bp);
struct buf *geteblk(int size);
struct buf *getblk (struct vnode *vp, off_t, int, int, int);
// from kern/vfs_subr.c
#define KERN_MAXVNODES           5      /* int: max vnodes */

// from sys/sysctl.h
extern int desiredvnodes;

// from sys/errno.h
#define EFTYPE          79              /* Inappropriate file type or format */

// from sys/fcntl.h
#define FREAD           0x0001
#define FWRITE          0x0002

// from sys/lock.h
#define LK_EXCLUSIVE    0x00000002      /* exclusive lock */
#define LK_RETRY        0x00020000 /* vn_lock: retry until locked */
#define LK_NOWAIT    0x00000010      /* do not sleep to await lock */

// from sys/libkern.h
#define bcmp(cs, ct, count) memcmp(cs, ct, count)

// from cpu/i386/include/param.h
#define MAXPHYS         (128 * 1024)    /* max raw I/O transfer size */

// inode
#define VA_UID_UUID_VALID        0x0004  /* uuid fields also populated */
#define     VNOVAL  (-1)
#define VA_GID_UUID_VALID        0x0008  /* uuid fields also populated */
//typedef signed long long int intmax_t;
int vm_page_count_severe(void);
int vget(struct vnode *vp, int flags);
void vdrop(struct vnode *vp);
int	nvtruncbuf (struct vnode *vp, off_t length, int blksize, int boff,int trivial);
int getnewvnode(enum vtagtype tag, struct mount *mp,struct vnode **vpp, int lktimeout, int lkflags);
void vx_put(struct vnode *vp);
void addaliasu(struct vnode *nvp, int x, int y);
void vsetflags(struct vnode *vp, int flags);
#define     VROOT   0x01    /* root of its file system */
#define VPFSROOT        0x00000100      /* may be a pseudo filesystem root */
int vinitvmio(struct vnode *vp, off_t filesize, int blksize, int boff);
void vhold_interlocked(struct vnode *vp);
#define  UF_NODUMP       0x00000001      /* do not dump file */
// inode.c

uid_t vop_helper_create_uid(struct mount *mp, mode_t dmode, uid_t duid, struct ucred *cred, unsigned short *modep);

// blockmap.c

void cpu_ccfence(void);
int vm_page_count_min(int donotcount);

// ioctl.c
#define PRIV_HAMMER_IOCTL        650     /* can hammer_ioctl(). */
#define PRIV_HAMMER_VOLUME       651     /* HAMMER volume management */

// signal.c
void lwkt_user_yield(void);

// from sys/signal2.h
#define CURSIG(lp)              __cursig(lp, 1, 0)
int __cursig(struct lwp *, int, int);

// from sys/buf.h
extern int      hidirtybufspace;

// from sys/kernel.h
extern const char *panicstr;        /* panic message */
extern int hz;                          /* system clock's frequency */
void lwkt_gettoken(lwkt_token_t tok);
void lwkt_reltoken(lwkt_token_t tok);

int
count_dev( unsigned long long  dev);
int
vcount(struct vnode *vp);

void BUF_KERNPROC(struct buf *bp);
//void            atomic_add_long(volatile unsigned long *, long);
void atomic_add_long(long int *v, long i);
#define PINTERLOCKED    0x00000400      /* Interlocked tsleep */

// from sys/iosched.h
void bwillwrite(int bytes);

// from sys/priv.h
#define PRIV_ROOT       1       /* Catch-all during development. */

int priv_check_cred(struct ucred *cred, int priv, int flags);

// from cpu/i386/include/limits.h
#define UQUAD_MAX       ULLONG_MAX      /* max value for a uquad_t */

/*
 * conflicting Linux definitions
 */

// in linux/module.h
#undef LIST_HEAD

// in linux/rbtree.h
#undef RB_BLACK
#undef RB_RED
#undef RB_ROOT

#endif /* _DFLY_WRAP_H */
