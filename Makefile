COMMON_WARN=-Wall -Werror -pedantic -Wno-logical-op-parentheses
DOC_WARN= -Wdocumentation -fparse-all-comments -Wno-documentation-deprecated-sync -Wdocumentation-unknown-command
CFLAGS=${COMMON_WARN} ${DOC_WARN} -std=gnu99 `pkg-config --cflags json-c`
LIBS=`pkg-config --libs json-c`

all:
	(echo char c_template[] = '"\n\'; cat funcs.c.template | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | awk '{print $$0 "\\n\\"}'; echo '";') >funcs.h
	clang ${CFLAGS} ${LIBS} main.c
	./a.out -j ./example/iso8583.json

run_example: all
	${MAKE} -C example
