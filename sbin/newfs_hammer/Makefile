PROG=	newfs_hammer
SRCS=	newfs_hammer.c crc32.c
MAN=
CC=gcc
CFLAGS=-Wall
newfs_hammer: crc32.o newfs_hammer.o 
	gcc -Wall crc32.o newfs_hammer.o -o newfs_hammer

clean:
	rm -f newfs_hammer newfs_hammer.o crc32.o
