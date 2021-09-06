#define getint(n, buf, sz, pos) do {n = natoi((char*)buf + pos, sz); pos += sz} while (0)
#define getbitmap(bm, buf, pos) do {memcpy(bm, buf, 8); pos += 8} while (0)
#define cpybitmap(dst, src) memcpy(dst, src, 16)

#define skipn(sz, pos) do {pos += sz} while (0)

#define isbitset(bm, bit) (bm[(bit - 1)/8] & (1 << (7 - ((bit - 1) & 7))))

#define arrsz(a) (sizeof(a)/sizeof(a[0]))

#define MAX_BIT 128

typedef char[16] bitmap;

static inline int natoi(const char *str, size_t sz) {
    char s[sz + 1];
    strncpy(s, str, sz + 1);
    return atoi(s);
}

static bool check_length_#protocol#(struct message *msg, uint8_t *buf, size_t size)
{
    int i;
    size_t msgpos = 0;
    bitmap bm;

    if (msgpos + 4 + 8 > size)
        goto err;

    skipn(4, msgpos); // Skip MTI
    getbitmap(bm, buf, msgpos);

    if (isbitset(bm, 1)) {
        if (msgpos + 8 > size)
            goto err;

        getbitmap(bm + 8, buf);
    }

    for (i = 2; i < MAX_BIT; ++i) {
        size_t len = 0;

        if (!isbitset(bm, i))
            continue;

        if (proto_#protocol#.flds[i].local)
            len = get_length_#protocol#(i, buf, size);
        else if (proto_#protocol#.flds[i].issizefxd)
            len = proto_#protocol#.flds[i].size;
        else {
            size_t n;

            len = proto_#protocol#.flds[i].size;

            if (msgpos + len > size)
                goto err;

            getint(n, buf, size, msgpos);
            len += n;
        }

        if (msgpos + len > size)
            goto err;

        skipn(len, msgpos);
    }

    return true;

err:
    fprintf(stderr, "Size of field is less than buffer\n");
    return false;
}

bool libfmmt_check_#protocol#(struct message *msg, uint8_t *buf, size_t size)
{
    int i;
    size_t msgpos, len;
    int mti;
    bitmap bm;

    if (check_length_#protocol#(msg, buf, size)) {
        fprintf(stderr, "Length of buffer is incorrect\n");
        return false;
    }

    getint(mti, buf, 4, msgpos);
    getbitmap(bm, buf, msgpos);

    if (isbitset(bm, 1))
        getbitmap(bm + 8, buf);

    for (i = 2; i < MAX_BIT; ++i) {
        uint8_t *fld;

        if (!isbitset(bm, i))
            continue;
        else if (!proto_#protocol#.flds[i].defined) {
            fprintf(stderr, "Can't find fld #%d in provided description.\n", i);
            break;
        }
        else if (proto_#protocol#.flds[i].local) {
            msgpos += check_#protocol#(i, buf + msgpos, size - msgpos);
            continue;
        }
        else if (proto_#protocol#.flds[i].issizefxd)
            len = proto_#protocol#.flds[i].size;
        else
            getint(len, buf, proto_#protocol#.flds[i].size, msgpos);

        if (proto_#protocol#.flds[i].bytes)
            continue;

        for (j = 0; j < len; ++j) {
            if (proto_#protocol#.flds[i].alpha && !isalpha(buf[msgpos + j]) && !isspace(buf[msgpos + j])
             || proto_#protocol#.flds[i].digit && !isdigit(buf[msgpos + j])) {
                fprintf(stderr, "Invalid byte in field #%d\n", i);
                return false;
            }
        }
    }

    return true;
}
