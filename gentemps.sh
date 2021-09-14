#!/bin/sh

(
    echo char c_template[] = '"\n\'
    cat funcs.c.template | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | awk '{print $0 "\\n\\"}'
    echo '";'
) >funcs.h
