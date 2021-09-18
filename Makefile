COMMON_WARN=-Wall -Weverything -Werror -pedantic -fparse-all-comments \
            -Wno-logical-op-parentheses -Wno-alloca -Wno-padded \
            -Wno-documentation-deprecated-sync
CFLAGS=${COMMON_WARN} -std=gnu99 `pkg-config --cflags json-c`
LIBS=`pkg-config --libs json-c`

all:
	objcopy --input binary --output elf64-x86-64 \
                --binary-architecture i386:x86-64 \
                --rename-section .data=.rodata,CONTENTS,ALLOC,LOAD,READONLY,DATA \
                --redefine-sym _binary_funcs_template_c_start=__template_data_start \
                --redefine-sym _binary_funcs_template_c_size=__template_data_size \
                funcs.template.c funcs.template.o
	clang ${CFLAGS} ${LIBS} funcs.template.o main.c
	./a.out -j ./example/iso8583.json

run_example: all
	${MAKE} -C example
