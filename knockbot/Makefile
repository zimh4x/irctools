# Generated automatically from Makefile.in by configure.
CC=gcc

BIN=../../../modules/knockbot.so
DEBUG=-O3
DEFINES=
INCLUDES= -I../include -I../../../include
CFLAGS=${DEBUG} ${DEFINES} ${INCLUDES} -Wall -O3 -march=nocona -pipe -fPIC
LFLAGS=${DEBUG} ${DEFINES} ${INCLUDES} -Wall -O3 -o
LIBS= -lnsl -ldl
OBJS=knockbot.o
LIBEXEC=${CC} ${DEBUG} -Wall -O3 -shared -fPIC -o ${BIN} ${OBJS}

all: ${OBJS} 
	${LIBEXEC}

*.c.${O}:
	${CC} ${CFLAGS} $*.c

clean:
	rm -f *.o ${BIN}
