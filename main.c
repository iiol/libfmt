#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>
#include <stdbool.h>
#include <libgen.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

#include <json_tokener.h>
#include <json_object.h>

extern char __template_data_start[]; static const char *c_template;
extern char __template_data_size[];  static size_t c_template_size;

/*
 * @brief           check_errormsg - remember and print error messages
 * @param[in]       msgerr - if is not NULL then put remember the msg print the msg
 */
static void
check_errormsg(const char *msgerr)
{
    static const char *s = NULL;

    if (msgerr)
        s = s ? s : msgerr;
    else {
        printf("%s", s ? s : "");
        s = NULL;
    }
}

static bool
check_flds(struct json_object *flds)
{
    size_t len, i;

    if (!json_object_is_type(flds, json_type_array)) {
        check_errormsg("fields is not an array\n");
        return false;
    }

    len = json_object_array_length(flds);
    for (i = 0; i < len; ++i) {
        struct json_object *fld;

        fld = json_object_array_get_idx(flds, i);
        if (!json_object_is_type(fld, json_type_object)
         || !json_object_is_type(json_object_object_get(fld, "idx"), json_type_int)
         || !json_object_is_type(json_object_object_get(fld, "descx"), json_type_string)
         && !json_object_is_type(json_object_object_get(fld, "descx"), json_type_null)
         || !json_object_is_type(json_object_object_get(fld, "format"), json_type_string)
         && !json_object_is_type(json_object_object_get(fld, "format"), json_type_null)) {
            check_errormsg("incorrect field in a field object\n");
            return false;
        }
    }

    return true;
}

static bool
check_proto(struct json_object *proto)
{
    if (!json_object_is_type(proto, json_type_object)
     || !json_object_is_type(json_object_object_get(proto, "protocol"), json_type_string)
     || !json_object_is_type(json_object_object_get(proto, "version"), json_type_string)
     || !check_flds(json_object_object_get(proto, "fields"))) {
        check_errormsg("incorrect fields in a protocol object\n");
        return false;
    }

    return true;
}

static bool
gen_header(struct json_object *proto, const char *header)
{
    const char *sproto;
    const char *svers;
    int fd;
    FILE *fp;
    char tmpfile[] = "/tmp/file.XXXXXX";
    char cmd[1024];

    sproto = json_object_get_string(json_object_object_get(proto, "protocol"));
    svers = json_object_get_string(json_object_object_get(proto, "version"));

    fd = mkstemp(tmpfile);
    if (fd == -1) {
        perror("mkstemp()");
        return false;
    }

    fp = fdopen(fd, "w+");
    if (!fp) {
        perror("fopen()");
        close(fd);
        unlink(tmpfile);
        return false;
    }

    fprintf(fp, "#include <stdlib.h>\n"
                "#include <stdbool.h>\n"
                "#include <stdint.h>\n");

    fprintf(fp, "struct proto_#protocol# {\n"
                "    const char *protocol;\n"
                "    const char *version;\n"
                "    struct fields_#protocol# {\n"
                "        bool isdefined;\n"
                "        const char *descx\n;"
                "        // format flags\n"
                "        bool issizefxd;\n"
                "        size_t size;\n"
                "        size_t max_size;\n"
                "        bool local;\n"
                "        bool alpha;\n"
                "        bool digit;\n"
                "        bool bytes;\n"
                "    } flds[128 + 1];\n"
                "};\n");

    fprintf(fp, "struct message {\n"
                "    void *userdata;\n"
                "    struct field {\n"
                "        size_t size;\n"
                "        uint8_t *data;\n"
                "    } flds[128 + 1];\n"
                "    // TODO add field tree\n"
                "};\n"
                "size_t get_length_#protocol#(int i, const uint8_t *buf, size_t size);\n"
                "size_t check_#protocol#(int i, const uint8_t *buf, size_t size);\n"
                "size_t parse_#protocol#(void *udata, int i, const uint8_t *buf, size_t size);\n"
                "size_t get_field_#protocol#(void **data, void *userdata, int i);\n"
                "\n"
                "bool libfmt_check_#protocol#(const struct message *msg, const uint8_t *buf, size_t size);\n"
                "struct message *libfmt_init_message_#protocol#(void);\n"
                "bool libfmt_parse_#protocol#(struct message *msg, const uint8_t *buf, size_t size);\n"
                "size_t libfmt_getfld_#protocol#(void **data, struct message *msg, int i);\n");

    fclose(fp);

    snprintf(cmd, sizeof (cmd), "/bin/cat %s | /bin/sed 's/#protocol#/%s/g' >%s", tmpfile, sproto, header);
    system(cmd);
    unlink(tmpfile);

    return true;
}

struct format_flags {
    bool issizefxd;
    int size;
    int max_size;
    bool islocal;
    bool isalpha;
    bool isdigit;
    bool isbytes;
};

/*
 * brief            parse_fmt - parse format string
 * param[out]       flgs - structure of flags of parsed format string
 * param[in]        fmt - format string
 * details          regex for *fmt*: /(a|n|s|an|as|ns|ans|b|x+n)\.{1,3}[0-9]{1,3}/
 */
static bool
parse_fmt(struct format_flags *flgs, const char *fmt)
{
    int i, len;

    if (!fmt) {
        fprintf(stderr, "fmt is NULL\n");
        return false;
    }

    if (!strcmp(fmt, "local")) {
        flgs->islocal = true;
        return true;
    }

    len = (int)strlen(fmt);

    memset(flgs, 0, sizeof (*flgs));
    flgs->issizefxd = true;

    for (i = 0; i < len; ++i) {
        if (fmt[i] == 'a')
            flgs->isalpha = true;
        else if (fmt[i] == 'n')
            flgs->isdigit = true;
        else if (fmt[i] == 's')
            ; // flgs->isspec = true; // TODO uncomment
        else if (fmt[i] == 'b')
            flgs->isbytes = true;
        else {
            if (fmt[i] == '.')
                flgs->issizefxd = false;
            else if (!isdigit(fmt[i])) {
                fprintf(stderr, "Unknown fmt symbol: '%c'\n", fmt[i]);
                return false;
            }

            break;
        }
    }

    // if we loop here than flgs->issizefxd == false
    for (; i < len; ++i) {
        if (fmt[i] != '.')
            break;

        flgs->size += 1;
    }

    if (i < len && !isdigit(fmt[i])) {
        int size = atoi(fmt + i);

        if (size < 1) {
            fprintf(stderr, "Size of field cant be less than 1\n");
            return false;
        }
        else if (flgs->issizefxd)
            flgs->size = size;

        flgs->max_size = size;
    }

    // normalizing
    if (flgs->isbytes)
        flgs->isalpha = flgs->isdigit = false;

    return true;
}

static int
gen_cfile(struct json_object *proto, const char *cfile, const char *hfile)
{
    int fd;
    int i, flds_count;
    struct json_object *flds;
    const char *sproto, *svers;
    char cmd[1024];
    char tmpfile[] = "/tmp/file.XXXXXX";
    FILE *fp;
    char *header;

    header = alloca(strlen(hfile) + 1);
    strcpy(header, hfile);
    header = basename(header);

    sproto = json_object_get_string(json_object_object_get(proto, "protocol"));
    svers = json_object_get_string(json_object_object_get(proto, "version"));
    flds = json_object_object_get(proto, "fields");
    flds_count = (int)json_object_array_length(flds);

    fd = mkstemp(tmpfile);
    if (fd == -1) {
        perror("mkstemp()");
        return 1;
    }

    fp = fdopen(fd, "w+");
    if (!fp) {
        perror("fopen()");
        close(fd);
        unlink(tmpfile);
        return 1;
    }

    fprintf(fp, "#ifndef _%s_H\n"
                "#define _%s_H\n", sproto, sproto);

    fprintf(fp, "#include <stdio.h>\n"
                "#include <stdlib.h>\n"
                "#include <string.h>\n"
                "#include <ctype.h>\n"
                "#include <stdint.h>\n"
                "#include <stdbool.h>\n"
                "#include \"%s\"\n", header);

    fprintf(fp, "struct proto_%s proto_%s = {\n"
                "    .protocol = \"%s\",\n"
                "    .version = \"%s\",\n"
                "    .flds = {\n", sproto, sproto, sproto, svers);


    for (i = 0; i < flds_count; ++i) {
        struct json_object *fld;
        int idx;
        const char *descx;
        const char *fmt;
        struct format_flags flgs = {0};

        fld = json_object_array_get_idx(flds, (size_t)i);
        idx = (int)json_object_get_int(json_object_object_get(fld, "idx")); // TODO: check 1 <= idx <= 128
        descx = json_object_get_string(json_object_object_get(fld, "descx"));
        fmt = json_object_get_string(json_object_object_get(fld, "format"));

        if (!parse_fmt(&flgs, fmt)) {
            fprintf(stderr, "Can't parse format string of #%d fld, fmt is '%s'", idx, fmt);
            return false;
        }

        // actually field with idx == 1 is additional bitmap and size of
        // the field depends on first bit of the field.
        // If firs bit is 0 than size is 8 byte (64 bit)
        // [0..........]
        //   |63 bits |
        // Otherwise size is 16 byte (128 bit)
        // [1..........]
        //   |127 bits|
        fprintf(fp, "        [%d] = {\n"
                    "            .isdefined = true,\n"
                    "            .descx = \"%s\",\n"
                    "            .issizefxd = %d,\n"
                    "            .size = %d,\n"
                    "            .max_size = %d,\n"
                    "            .local = %d,\n"
                    "            .alpha = %d,\n"
                    "            .digit = %d,\n"
                    "            .bytes = %d,\n"
                    "        },\n", idx, descx, flgs.issizefxd, flgs.size,
                                    flgs.max_size, flgs.islocal,
                                    flgs.isalpha, flgs.isdigit,
                                    flgs.isbytes);
    }

    fprintf(fp, "    }\n};\n");
    fprintf(fp, "%.*s", (int)c_template_size, c_template);
    fprintf(fp, "#endif\n");

    fclose(fp);

    snprintf(cmd, sizeof (cmd), "/bin/cat %s | /bin/sed 's/#protocol#/%s/g' >%s", // TODO: rewrite
             tmpfile, sproto, cfile);

    system(cmd); // TODO: rewrite
    unlink(tmpfile);

    return 0;
}

static int
libgen(struct json_object *proto, const char *cfile, const char *hfile)
{
    gen_header(proto, hfile);
    gen_cfile(proto, cfile, hfile);

    return 0;
}

static void
usage(FILE *stream, const char *file)
{
    fprintf(stream, "Usage: %s <-j file.json>\n", file);
}

/*
 * @brief           filenam - get filename of a file without an extention
 * @param[in,out]   file - path to the file
 * @details         some examples:
 *                  '/path/to/file.c' -> 'file'
 *                  './file.tar.gz'  -> 'file.tar'
 * @todo            Fix for files that start with a dot
 */
static char*
filename(char *file)
{
    char *p = NULL;
    char *ret = file;

    if (!file)
        return NULL;

    for (; *file; ++file) {
        if (*file == '/')
            ret = file + 1;
        else if (*file == '.')
            p = file;
    }

    if (p)
        *p = '\0';

    return ret;
}

int
main(int argc, char **argv)
{
    FILE *jsonf;
    int rc = 0;
    char *json_str;
    long size = 0L;
    struct json_object *proto;
    char c;
    const char *json_file = NULL;
    char *cfile = NULL, *hfile= NULL, *path, *file;
    int len;

    c_template = __template_data_start;
    c_template_size = (size_t)__template_data_size;

    while ((c = (char)getopt(argc, argv, "c:j:h:")) != -1) {
        switch (c) {
        case 'j':
            json_file = optarg;
            break;

        default:
            usage(stderr, *argv);
            return 1;
        }
    }

    if (!json_file) {
        usage(stderr, *argv);
        return 1;
    }

    len = (int)strlen(json_file) + 1;
    cfile = alloca(len);
    hfile = alloca(len);
    path = alloca(len);
    file = alloca(len);

    strcpy(path, json_file);
    strcpy(file, json_file);

    path = dirname(path);
    file = filename(file);

    sprintf(cfile, "%s/%s.c", path, file);
    sprintf(hfile, "%s/%s.h", path, file);

    // Open a json file
    jsonf = fopen(json_file, "r");
    if (!jsonf) {
        perror("fopen()");
        rc = 1;
        goto ret;
    }

    // Allocate buffer for the json file and copy it
    fseek(jsonf, 0L, SEEK_END); // TODO: check retval
    size = ftell(jsonf); // TODO: check retval
    json_str = alloca(size); // TODO: check retval
    fseek(jsonf, 0L, SEEK_SET); // TODO: check retval
    fread(json_str, 1, (unsigned long)size, jsonf);
    if (ferror(jsonf)) {
        fprintf(stderr, "Can't read file %s\n", json_file);
        rc = 1;
        goto close_file;
    }

    proto = json_tokener_parse(json_str);
    if (!proto) {
        fprintf(stderr, "Can't parse file %s\n", json_file);
        rc = 1;
        goto close_file;
    }

    if (!check_proto(proto)) {
        check_errormsg(NULL);
        goto free_json;
    }

    libgen(proto, cfile, hfile);

free_json:
    (void)proto; // TODO: free json
close_file:
    fclose(jsonf);
ret:
    return rc;
}
