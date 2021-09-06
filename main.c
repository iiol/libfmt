#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>
#include <stdbool.h>

#include <json_tokener.h>
#include <json_object.h>

#define JFILE "iso8583.json"
#define TEMPLC "funcs.c"

/*
 * if msgerr isn't equal to NULL then remember a message, otherwise print the message
 */
void
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

bool
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

bool
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

int
gen_includes(struct json_object *proto)
{
    (void)proto;

    printf("#include <stdio.h>\n");
    printf("#include <stdlib.h>\n");
    printf("#include <string.h>\n");

    return 0;
}

int
gen_protocol(struct json_object *proto)
{
    size_t i, flds_count;
    const char *sproto;
    const char *svers;
    struct json_object *flds;

    sproto = json_object_get_string(json_object_object_get(proto, "protocol"));
    svers = json_object_get_string(json_object_object_get(proto, "version"));
    flds = json_object_object_get(proto, "fields");
    flds_count = json_object_array_length(flds);

    printf("struct proto_%s {\n"
           "    const char *protocol;\n"
           "    const char *version;\n"
           "    struct fields_%s {\n"
           "        int idx;\n"
           "        const char *descx\n;"
           "        const char *fmt;\n"
           "        size_t size;\n"
           "    } flds[%d];\n"
           "} proto_%s = {\n"
           "    .protocol = \"%s\",\n"
           "    .version = \"%s\",\n"
           "    .flds = {\n", sproto, sproto, (int)flds_count, sproto, sproto, svers);


    for (i = 0; i < flds_count; ++i) {
        struct json_object *fld;
        int idx;
        const char *descx;
        const char *fmt;

        fld = json_object_array_get_idx(flds, i);
        idx = json_object_get_int(json_object_object_get(fld, "idx"));
        descx = json_object_get_string(json_object_object_get(fld, "descx"));
        fmt = json_object_get_string(json_object_object_get(fld, "format"));
        printf("        [%d] = {\n"
               "            .descx = \"%s\",\n"
               "            .fmt = \"%s\",\n"
               "            .size = %d,\n"
               "        },\n", idx, descx, fmt, 0);
    }

    printf("    }\n};\n");

    return 0;
}

int
gen_message(struct json_object *proto)
{
    const char *sproto;

    sproto = json_object_get_string(json_object_object_get(proto, "protocol"));

    // put into h file
    printf("struct message {\n"
           "    void *userdata;\n"
           "    // TODO add field tree\n"
           "};\n");

    return 0;
}

int
gen_functions(struct json_object *proto)
{
    const char *sproto;
    char cmd[1024];

    sproto = json_object_get_string(json_object_object_get(proto, "protocol"));

    snprintf(cmd, sizeof (cmd), "/bin/cat %s | /bin/sed 's/#protocol#/%s/g' >%s.%s", TEMPLC, sproto, sproto, TEMPLC);
    system(cmd); // TODO: rewrite

    // regex for *format*
    // /(a|n|x+n|s|an|as|ns|ans|b|x+n)\.\.?\.?NN?N?/
    // TODO: build .c file from template (funcs.c)

    return 0;
}

int
libgen(struct json_object *proto)
{
    gen_includes(proto);
    gen_protocol(proto);
    gen_message(proto);
    gen_functions(proto);

    return 0;
}

int
main(void)
{
    FILE *jsonf;
    int rc = 0;
    char *json_str;
    size_t size = 0L;
    struct json_object *proto;

    // Open a json file
    jsonf = fopen(JFILE, "r");
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
        fprintf(stderr, "Can't read file %s\n", JFILE);
        rc = 1;
        goto close_file;
    }

    proto = json_tokener_parse(json_str);
    if (!proto) {
        fprintf(stderr, "Can't parse file %s\n", JFILE);
        rc = 1;
        goto close_file;
    }

    if (!check_proto(proto)) {
        check_errormsg(NULL);
        goto free_json;
    }

    libgen(proto);

free_json:
    (void)proto; // TODO: free json
close_file:
    fclose(jsonf);
ret:
    return rc;
}
