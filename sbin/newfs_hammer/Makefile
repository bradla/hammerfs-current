PROG=	newfs_hammer
SRCS=	newfs_hammer.c crc32.c
MAN=
CC=gcc
CFLAGS=-Wall -I${.CURDIR}/../../dfly/sys -I../libhammer -DALIST_NO_DEBUG -luuid -lcrypto -lssl -lm -lutil -L../libhammer -lhammer -lbsd 
newfs_hammer: crc32.o newfs_hammer.o  
	gcc -I${.CURDIR}/../../dfly/sys -I../libhammer -DALIST_NO_DEBUG -luuid -lcrypto -lssl -lm -lutil -L../libhammer -lhammer -lbsd crc32.o newfs_hammer.o ../hammer/ondisk.o -o newfs_hammer

clean:
	rm -f newfs_hammer newfs_hammer.o crc32.o
