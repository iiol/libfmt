#define getint(n, buf, sz, pos) do {n = natoi((char*)buf + pos, sz); pos += sz;} while (0)
#define getbitmap(bm, buf, pos) do {memcpy(bm, (char*)buf + pos, 8); pos += 8;} while (0)
#define cpybitmap(dst, src) memcpy(dst, src, 16)
#define getraw(dest, src, len, pos) do {memcpy(dest, (char*)src + pos, len); pos += len;} while (0)

#define printbitmap(bm) do {    \
    printf("bitmap: ");         \
    for (i = 0; i < 16; ++i)    \
        printf("%02X", bm[i]);  \
    printf("\n");               \
} while (0)

#define skipn(sz, pos) do {pos += sz;} while (0)

#define isbitset(bm, bit) (bm[(bit - 1)/8] & (1 << (7 - ((bit - 1) & 7))))

#define arrsz(a) (sizeof(a)/sizeof(a[0]))

#define MAX_BIT 128

typedef uint8_t bitmap[MAX_BIT/8];

static inline int natoi(const char *str, unsigned int len) {
    char s[len + 1];
    memcpy(s, str, len);
    s[len] = '\0';
    return atoi(s);
}

static bool
check_length_#protocol#(const struct message *msg, const uint8_t *buf, size_t size)
{
    int i;
    size_t msgpos = 0;
    bitmap bm;

    for (i = 0; i <= MAX_BIT; ++i) {
        size_t len = 0;

        if (i = 1) { // BITMAP
            getbitmap(bm, buf, msgpos);

            if (isbitset(bm, 1)) {
                if (msgpos + 8 > size)
                    goto err;

                getbitmap(bm + 8, buf, msgpos);
            }
        }
        else if (i != 0 && !isbitset(bm, i)) // Don't continue for MTI
            continue;

        if (proto_#protocol#.flds[i].local)
            len = get_length_#protocol#(i, buf, size);
        else if (proto_#protocol#.flds[i].issizefxd)
            len = proto_#protocol#.flds[i].size; // TODO: check max size
        else {
            size_t n;

            len = proto_#protocol#.flds[i].size;

            if (msgpos + len > size)
                goto err;

            getint(n, buf, len, msgpos);
            len = n;
        }

        if (msgpos + len > size)
            goto err;

        skipn(len, msgpos);
    }

    if (msgpos != size) {
        fprintf(stderr, "Length of buffer is more than read size\n");
        return false;
    }

    return true;

err:
    fprintf(stderr, "Size of buffer is less than size of field\n");
    return false;
}

bool
libfmt_check_#protocol#(const struct message *msg, const uint8_t *buf, size_t size)
{
    int i;
    size_t msgpos = 0, len;
    int mti;
    bitmap bm = {0};

    if (!check_length_#protocol#(msg, buf, size)) {
        fprintf(stderr, "Length of buffer is incorrect\n");
        return false;
    }

    for (i = 0; i <= MAX_BIT; ++i) {
        int j;

        if (i == 1) {
            getbitmap(bm, buf, msgpos);

            if (isbitset(bm, 1))
                getbitmap((uint8_t*)bm + 8, buf, msgpos);
        }
        else if (!isbitset(bm, i))
            continue;

        if (!proto_#protocol#.flds[i].isdefined) {
            fprintf(stderr, "Can't find fld #%d in provided description\n", i);
            return false;
        }

        printf("Checking field #%d\n", i);

        if (proto_#protocol#.flds[i].local) {
            msgpos += check_#protocol#(i, buf + msgpos, size - msgpos); // TODO: put msg
            continue;
        }
        else if (i == 1)
            len = isbitset(bm, 1) : 16 : 8;
        else if (proto_#protocol#.flds[i].issizefxd)
            len = proto_#protocol#.flds[i].size;
        else
            getint(len, buf, proto_#protocol#.flds[i].size, msgpos);

        if (proto_#protocol#.flds[i].bytes) {
            msgpos += len;
            continue;
        }

        for (j = 0; j < len; ++j) {
            if (proto_#protocol#.flds[i].alpha && !isalpha(buf[msgpos + j]) && !isspace(buf[msgpos + j])
             || proto_#protocol#.flds[i].digit && !isdigit(buf[msgpos + j])) {
                fprintf(stderr, "Invalid byte in field #%d\n", i);
                return false;
            }
        }

        msgpos += j;
    }

    return true;
}

struct message*
libfmt_init_message_#protocol#(void)
{
    struct message *msg;
    int i;

    msg = malloc(sizeof (*msg));
    memset(msg, 0, sizeof (*msg));

    for (i = 0; i < MAX_BIT; ++i) {
        if (!proto_#protocol#.flds[i].isdefined
         || proto_#protocol#.flds[i].local)
            continue;

        if (i == 1)
            msg->flds[i].data = malloc(MAX_BIT/8);
        else
            msg->flds[i].data = malloc(proto_#protocol#.flds[i].max_size);
    }

    return msg;
}

bool
libfmt_parse_#protocol#(struct message *msg, const uint8_t *buf, size_t size)
{
    int i;
    size_t msgpos = 0, len;
    int mti;
    bitmap bm = {0};

    if (!libfmt_check_#protocol#(msg, buf, size)) {
        fprintf(stderr, "Can't parse a message\n");
        return false;
    }

    getint(mti, buf, 4, msgpos);
    getbitmap(bm, buf, msgpos);

    if (isbitset(bm, 1))
        getbitmap((uint8_t*)bm + 8, buf, msgpos);

    // TODO: CONTINUE HERE
    for (i = 2; i < MAX_BIT; ++i) {
        if (!isbitset(bm, i))
            continue;
        else if (proto_#protocol#.flds[i].local) {
            msgpos += parse_#protocol#(msg->userdata, i, buf + msgpos, size - msgpos);
            continue;
        }
        else if (proto_#protocol#.flds[i].issizefxd)
            len = proto_#protocol#.flds[i].size;
        else
            getint(len, buf, proto_#protocol#.flds[i].size, msgpos);

        msg->flds[i].size = len;
        getraw(msg->flds[i].data, buf, len, msgpos);
    }

    return true;
}

size_t
libfmt_getfld_#protocol#(void **data, struct message *msg, int i)
{
    if (i <= 1 || i > 128)
        return 0;

    if (proto_#protocol#.flds[i].local)
        return get_field_#protocol#(data, msg->userdata, i);

    *data = msg->flds[i].data;
    return msg->flds[i].size;
}
