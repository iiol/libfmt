#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

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

size_t
parse_iso8583(void *udata, int i, const uint8_t *msg, size_t size)
{
    return 0;
}

size_t
get_field_iso8583(void **data, void *userdata, int i)
{
    return 0;
}

int
main(void)
{
    struct message *msg;
    const char *field2;
    size_t size;
    uint8_t valid_buf[] = "0100\xc0\x00\x00\x00\x00\x00\x00\x00"
                          "\x00\x00\x00\x00\x00\x00\x00\x00"
                          "12123456789012";
    uint8_t invalid_buf1[] =  "0100\xc0\x00\x00\x00\x00\x00\x00\x00"
                              "\x00\x00\x00\x00\x00\x00\x00\x00"
                              "1212345678901";
    uint8_t invalid_buf2[] =  "0100\xc0\x00\x00\x00\x00\x00\x00\x00"
                              "\x00\x00\x00\x00\x00\x00\x00\x00"
                              "121234567890123";

    msg = libfmt_init_message_iso8583();

    assert(libfmt_check_iso8583(msg, (const uint8_t*)valid_buf, sizeof (valid_buf) - 1));
    assert(!libfmt_check_iso8583(msg, (const uint8_t*)invalid_buf1, sizeof (invalid_buf1) - 1));
    assert(!libfmt_check_iso8583(msg, (const uint8_t*)invalid_buf2, sizeof (invalid_buf2) - 1));

    // TODO: write libfmt_clean_message_#protocol#
    free(msg);
    msg = libfmt_init_message_iso8583();

    libfmt_parse_iso8583(msg, valid_buf, sizeof (valid_buf) - 1);
    size = libfmt_getfld_iso8583((void**)&field2, msg, 2);

    printf("field 2: %.*s, len: %d\n", (int)size, field2, (int)size);

    free(msg);

    return 0;
}
