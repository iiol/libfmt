#!/bin/sh

(
    echo 'static char c_template[] = ' '"\n\'
    cat funcs.c.template | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | awk '{print $0 "\\n\\"}'
    echo '";'
) >funcs.h
