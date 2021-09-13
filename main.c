#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>
#include <stdbool.h>
#include <libgen.h>
#include <unistd.h>
#include <fcntl.h>

#include <json_tokener.h>
#include <json_object.h>

#include "funcs.h"

/*
 * @brief           check_errormsg - remember and print error messages
 * @param[in]       msgerr -- if is not NULL then put remember the msg print the msg
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

static int
gen_header(struct json_object *proto, const char *header)
{
    const char *sproto;
    const char *svers;
    FILE *fp;

    sproto = json_object_get_string(json_object_object_get(proto, "protocol"));
    svers = json_object_get_string(json_object_object_get(proto, "version"));

    fp = fopen(header, "w+");
    if (!fp) {
        perror("fopen()");
        return 1;
    }

    fprintf(fp, "#include <stdlib.h>\n"
                "#include <stdbool.h>\n"
                "#include <stdint.h>\n");

    fprintf(fp, "struct proto_%s {\n"
                "    const char *protocol;\n"
                "    const char *version;\n"
                "    struct fields_%s {\n"
                "        bool isdefined;\n"
                "        const char *descx\n;"
                "        // format flags\n"
                "        bool issizefxd;\n"
                "        size_t size;\n"
                "        bool local;\n"
                "        bool alpha;\n"
                "        bool digit;\n"
                "        bool bytes;\n"
                "    } flds[128];\n"
                "};\n", sproto, sproto);

    fprintf(fp, "struct message {\n"
                "    void *userdata;\n"
                "    // TODO add field tree\n"
                "};\n"
                "size_t get_length_%s(int i, const uint8_t *buf, size_t size);\n"
                "size_t check_%s(int i, const uint8_t *buf, size_t size);\n"
                "bool libfmt_check_%s(struct message *msg, const uint8_t *buf, size_t size);\n", sproto, sproto, sproto);

    return 0;
}

static int
gen_cfile(struct json_object *proto, const char *cfile, const char *hfile)
{
    int fd;
    size_t i, flds_count;
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
    flds_count = json_object_array_length(flds);

    fd = mkstemp(tmpfile);
    if (fd == -1) {
        perror("mkstemp()");
        return 1;
    }

    fp = fdopen(fd, "w+");
    if (!fp) {
        perror("fopen()");
        close(fd);
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

        fld = json_object_array_get_idx(flds, i);
        idx = json_object_get_int(json_object_object_get(fld, "idx")); // TODO
        descx = json_object_get_string(json_object_object_get(fld, "descx"));
        fmt = json_object_get_string(json_object_object_get(fld, "format"));
        fprintf(fp, "        [%d] = {\n"
                    "            .isdefined = true,\n"
                    "            .descx = \"%s\",\n"
                    "            .issizefxd = true,\n" // TODO
                    "            .size = %d,\n"
                    "            .local = false,\n" // TODO
                    "            .alpha = false,\n" // TODO
                    "            .digit = false,\n" // TODO
                    "            .bytes = true,\n" // TODO
                    "        },\n", idx, descx, 0);
    }

    fprintf(fp, "    }\n};\n");
    fprintf(fp, "%s", c_template);
    fprintf(fp, "#endif\n");

    fclose(fp);

    snprintf(cmd, sizeof (cmd), "/bin/cat %s | /bin/sed 's/#protocol#/%s/g' >%s", // TODO
             tmpfile, sproto, cfile);

    system(cmd); // TODO: rewrite
    unlink(tmpfile);

    // regex for *format*
    // /(a|n|x+n|s|an|as|ns|ans|b|x+n)\.\.?\.?NN?N?/
    // TODO: build .c file from template (funcs.c)

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
    size_t size = 0L;
    struct json_object *proto;
    char c;
    const char *json_file = NULL;
    char *cfile = NULL, *hfile= NULL, *path, *file;
    int len;


    while ((c = getopt(argc, argv, "c:j:h:")) != -1) {
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

    len = strlen(json_file) + 1;
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
    fread(json_str, 1, size, jsonf);
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
