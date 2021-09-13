#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "iso8583.h"

size_t
get_length_iso8583(int idx, const uint8_t *buf, size_t size)
{
    return 0;
}

size_t
check_iso8583(int idx, const uint8_t *buf, size_t size)
{
    return 0;
}

int
main(void)
{
    struct message msg;
    uint8_t buf[] = "0100\xc0\x00\x00\x00\x00\x00\x00\x00""\x00\x00\x00\x00\x00\x00\x00\x00";

    if (libfmt_check_iso8583(&msg, (const uint8_t*)buf, sizeof (buf) - 1))
        printf("ok\n");
    else
        printf("nok\n");

    return 0;
}
