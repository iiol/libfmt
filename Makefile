COMMON_WARN=-Wall -Weverything -Werror -pedantic -fparse-all-comments \
            -Wno-logical-op-parentheses -Wno-alloca -Wno-padded \
            -Wno-documentation-deprecated-sync
CFLAGS=${COMMON_WARN} -std=gnu99 `pkg-config --cflags json-c`
LIBS=`pkg-config --libs json-c`

all:
	./gentemps.sh
	clang ${CFLAGS} ${LIBS} main.c
	./a.out -j ./example/iso8583.json

run_example: all
	${MAKE} -C example
