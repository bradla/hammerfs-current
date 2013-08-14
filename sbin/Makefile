MAN=	hammer.8 newfs_hammer.8
#CFLAGS+= -I${.CURDIR}/../dfly/sys -DALIST_NO_DEBUG -luuid -lcrypto -lssl -lm -lutil -L../libhammer/libhammer.a -lhammer -lbsd
LDFLAGS= -Llibhammer -lhammer -lm -lutil -lcrypto -lssl -lbsd -luuid

all: libhammer.a hammer newfs_hammer 

libhammer.a:
	cd libhammer; make all

hammer:
	gcc $(LDFLAGS) -o hammer libhammer/crc32.c ondisk.c blockmap.c cache.c misc.c cycle.c \
	cmd_show.c cmd_softprune.c cmd_history.c \
	cmd_blockmap.c cmd_reblock.c cmd_rebalance.c \
	cmd_synctid.c cmd_stats.c cmd_remote.c \
	cmd_pseudofs.c cmd_snapshot.c cmd_mirror.c cmd_status.c \
	cmd_cleanup.c cmd_info.c cmd_version.c cmd_volume.c \
	cmd_config.c cmd_recover.c cmd_dedup.c \
	uuid_create.c uuid_from_string.c uuid_name_lookup.c \
	uuid_to_string.c uuid_compare.c uuid_is_nil.c uuid_create_nil.c \
	sysctlnametomib.c humanize_unsigned.c getmntinfo.c getdevpath.c hammer.c

newfs_hammer:
	gcc -lbsd -luuid -o newfs_hammer libhammer/crc32.c ondisk.c blockmap.c cache.c \
	uuid_is_nil.c uuid_to_string.c uuid_create_nil.c uuid_from_string.c uuid_create.c \
	uuid_name_lookup.c uuid_compare.c newfs_hammer.c  

clean:
	rm hammer newfs_hammer

#$(EXECUTABLE): $(OBJECTS) 
#	$(CC) $(LDFLAGS) $(OBJECTS) -o $@
