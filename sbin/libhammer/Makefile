SRCS=	crc32.c info.c misc.c
INCS=	libhammer.h
MAN=	 libhammer_get_volinfo.3
CC = gcc
CFLAGS = -Wall -fPIC
utilObjs = crc32.o info.o misc.o

all:  libhammer.a

libhammer.a: $(utilObjs)
	ar rc $@ $(utilObjs)
	ranlib $@
	gcc -shared -Wl,-soname,libhammer.so -o libhammer.so   *.o

clean:
	rm *.so *.o *.a
