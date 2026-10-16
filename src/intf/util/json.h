#ifndef ROOTVIEW_UTIL_JSON_H
#define ROOTVIEW_UTIL_JSON_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT,
} json_type_t;

typedef struct json_value json_value_t;

struct json_value {
    json_type_t type;
    union {
        bool boolean;
        double number;
        char *string;
        struct {
            json_value_t **items;
            size_t count;
        } array;
        struct {
            char **keys;
            json_value_t **values;
            size_t count;
        } object;
    } as;
};

/* parsing */
json_value_t *json_parse(const char *text, char *err, size_t err_len);
json_value_t *json_parse_file(const char *path, char *err, size_t err_len);
void json_free(json_value_t *v);

/* object/array access, all read paths tolerate NULL and missing keys */
json_value_t *json_get(const json_value_t *obj, const char *key);
const char *json_get_string(const json_value_t *obj, const char *key, const char *fallback);
long json_get_int(const json_value_t *obj, const char *key, long fallback);
bool json_get_bool(const json_value_t *obj, const char *key, bool fallback);

/* construction */
json_value_t *json_new_object(void);
json_value_t *json_new_array(void);
void json_object_set(json_value_t *obj, const char *key, json_value_t *val);
void json_object_set_string(json_value_t *obj, const char *key, const char *val);
void json_object_set_int(json_value_t *obj, const char *key, long val);
void json_object_set_bool(json_value_t *obj, const char *key, bool val);
void json_array_push(json_value_t *arr, json_value_t *val);

/* output */
char *json_to_string(const json_value_t *v, bool pretty);
int json_write_file(const json_value_t *v, const char *path);

#endif
