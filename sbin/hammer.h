/*
 * Copyright (c) 2007 The DragonFly Project.  All rights reserved.
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
 * $DragonFly: src/sbin/hammer/hammer.h,v 1.27 2008/11/13 02:04:27 dillon Exp $
 */

#include <stdint.h>
#include <sys/types.h>
#include "../dfly/sys/diskslice.h"
#include "../dfly/sys/diskmbr.h"
#include <sys/stat.h>
#include <time.h>
#include <sys/wait.h>
/* #ifdef HAVE_GETMNTINFO */
#include <paths.h>
#include <sys/param.h>
#include <sys/mount.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <err.h>
#include <ctype.h>
#include <signal.h>
#include <dirent.h>
#include "../dfly/sys/uuid.h"

#include "hammer_util.h"
#include "../hammer_ioctl.h"

#include "libhammer/libhammer.h"


#define GETDEVPATH_RAWDEV       0x0001
#define _PATH_DEVTAB_PATHS \
        "/usr/local/etc:/etc:/etc/defaults"

#define SIGINFO            29
/*
 * Flags for various system call interfaces.
 *
 * waitfor flags to vfs_sync() and getfsstat()
 */
#define MNT_WAIT        0x0001  /* synchronously wait for I/O to complete */
#define MNT_NOWAIT      0x0002  /* start all I/O, but do not wait for it */
#define MNT_LAZY        0x0004  /* be lazy and do not necessarily push it all */

/* Status codes returned by the functions. */
#define uuid_s_ok                       0
#define uuid_s_bad_version              1
#define uuid_s_invalid_string_uuid      2
#define uuid_s_no_memory                3

/*
 * file system statistics
 */

#define MFSNAMELEN	16	/* length of fs type name, including null */
#define	MNAMELEN	80	/* length of buffer for returned name */

struct statfs {
	long	f_spare2;		/* placeholder */
	long	f_bsize;		/* fundamental file system block size */
	long	f_iosize;		/* optimal transfer block size */
	long	f_blocks;		/* total data blocks in file system */
	long	f_bfree;		/* free blocks in fs */
	long	f_bavail;		/* free blocks avail to non-superuser */
	long	f_files;		/* total file nodes in file system */
	long	f_ffree;		/* free file nodes in fs */
	fsid_t	f_fsid;			/* file system id */
	uid_t	f_owner;		/* user that mounted the filesystem */
	int	f_type;			/* type of filesystem */
	int	f_flags;		/* copy of mount exported flags */
	long    f_syncwrites;		/* count of sync writes since mount */
	long    f_asyncwrites;		/* count of async writes since mount */
	char	f_fstypename[MFSNAMELEN]; /* fs type name */
	char	f_mntonname[MNAMELEN];	/* directory on which mounted */
	long    f_syncreads;		/* count of sync reads since mount */
	long    f_asyncreads;		/* count of async reads since mount */
	short	f_spares1;		/* unused spare */
	char	f_mntfromname[MNAMELEN];/* mounted filesystem */
	short	f_spares2;		/* unused spare */
	long    f_spare[2];		/* unused spare */
};

extern int RecurseOpt;
extern int VerboseOpt;
extern int QuietOpt;
extern int TwoWayPipeOpt;
extern int TimeoutOpt;
extern int DelayOpt;
extern char *SshPort;
extern int CompressOpt;
extern int ForceYesOpt;
extern int RunningIoctl;
extern int DidInterrupt;
extern int ForceOpt;
extern int BulkOpt;
extern u_int64_t BandwidthOpt;
extern u_int64_t SplitupOpt;
extern u_int64_t MemoryLimit;
extern const char *SplitupOptStr;
extern const char *LinkPath;
extern const char *CyclePath;

/* XXX conflicting type param 1 void hammer_cmd_show(hammer_tid_t node_offset, u_int32_t lo,int64_t obj_id, int depth, hammer_base_elm_t left_bound, hammer_base_elm_t right_bound); */

void hammer_cmd_show(hammer_off_t node_offset, u_int32_t lo, int64_t obj_id,	int depth,hammer_base_elm_t left_bound, hammer_base_elm_t right_bound);
void hammer_cmd_show_undo(void);
void hammer_cmd_sshremote(const char *cmd, const char *target);
void hammer_cmd_recover(const char *target_dir);
void hammer_cmd_checkmap(void);
void hammer_cmd_prune(char **av, int ac);
void hammer_cmd_softprune(char **av, int ac, int everything_opt);
void hammer_cmd_bstats(char **av, int ac);
void hammer_cmd_iostats(char **av, int ac);
void hammer_cmd_synctid(char **av, int ac);
void hammer_cmd_mirror_read(char **av, int ac, int streaming);
void hammer_cmd_mirror_write(char **av, int ac);
void hammer_cmd_mirror_copy(char **av, int ac, int streaming);
void hammer_cmd_mirror_dump(void);
void hammer_cmd_history(const char *offset_str, char **av, int ac);
void hammer_cmd_blockmap(void);
void hammer_cmd_reblock(char **av, int ac, int flags);
void hammer_cmd_rebalance(char **av, int ac);
void hammer_cmd_pseudofs_status(char **av, int ac);
void hammer_cmd_pseudofs_create(char **av, int ac, int is_slave);
void hammer_cmd_pseudofs_update(char **av, int ac);
void hammer_cmd_pseudofs_destroy(char **av, int ac);
void hammer_cmd_pseudofs_upgrade(char **av, int ac);
void hammer_cmd_pseudofs_downgrade(char **av, int ac);
void hammer_cmd_status(char **av, int ac);
void hammer_cmd_snapshot(char **av, int ac);
void hammer_cmd_snap(char **av, int ac, int tostdout, int fsbase);
void hammer_cmd_snapls(char **av, int ac);
void hammer_cmd_snaprm(char **av, int ac);
void hammer_cmd_cleanup(char **av, int ac);
void hammer_cmd_config(char **av, int ac);
void hammer_cmd_viconfig(char **av, int ac);
void hammer_cmd_info(void);
void hammer_cmd_get_version(char **av, int ac);
void hammer_cmd_set_version(char **av, int ac);
void hammer_cmd_volume_add(char **av, int ac);
void hammer_cmd_volume_del(char **av, int ac);
void hammer_cmd_volume_list(char **av, int ac);
void hammer_cmd_dedup_simulate(char **av, int ac);
void hammer_cmd_dedup(char **av, int ac);

void hammer_get_cycle(hammer_base_elm_t base, hammer_tid_t *tidp);
void hammer_set_cycle(hammer_base_elm_t base, hammer_tid_t tid);
void hammer_reset_cycle(void);

int getpfs(struct hammer_ioc_pseudofs_rw *pfs, const char *path);
void relpfs(int fd, struct hammer_ioc_pseudofs_rw *pfs);
void hammer_check_restrict(const char *path);
