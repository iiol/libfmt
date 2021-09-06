CFLAGS=-Wall -Werror -pedantic -Wno-logical-op-parentheses `pkg-config --cflags json-c`
LIBS=`pkg-config --libs json-c`

all:
	clang ${CFLAGS} ${LIBS} main.c
