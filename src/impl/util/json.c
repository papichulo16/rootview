#include "util/json.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *src;
    size_t pos;
    char *err;
    size_t err_len;
    bool failed;
} parser_t;

static json_value_t *parse_value(parser_t *p);

static void set_err(parser_t *p, const char *msg) {
    if (p->failed) return;
    p->failed = true;
    if (p->err && p->err_len > 0) {
        snprintf(p->err, p->err_len, "%s (at offset %zu)", msg, p->pos);
    }
}

static void skip_ws(parser_t *p) {
    while (isspace((unsigned char) p->src[p->pos])) p->pos++;
}

static json_value_t *alloc_value(json_type_t type) {
    json_value_t *v = calloc(1, sizeof(json_value_t));
    v->type = type;
    return v;
}

static char *parse_string_raw(parser_t *p) {
    if (p->src[p->pos] != '"') {
        set_err(p, "expected string");
        return NULL;
    }
    p->pos++;
    size_t cap = 32, len = 0;
    char *buf = malloc(cap);
    while (p->src[p->pos] != '"') {
        char c = p->src[p->pos];
        if (c == '\0') {
            set_err(p, "unterminated string");
            free(buf);
            return NULL;
        }
        if (c == '\\') {
            p->pos++;
            char esc = p->src[p->pos];
            switch (esc) {
                case 'n': c = '\n'; break;
                case 't': c = '\t'; break;
                case 'r': c = '\r'; break;
                case '"': c = '"'; break;
                case '\\': c = '\\'; break;
                case '/': c = '/'; break;
                default: c = esc; break;
            }
        }
        if (len + 1 >= cap) {
            cap *= 2;
            buf = realloc(buf, cap);
        }
        buf[len++] = c;
        p->pos++;
    }
    p->pos++;
    buf[len] = '\0';
    return buf;
}

static json_value_t *parse_string(parser_t *p) {
    char *s = parse_string_raw(p);
    if (!s) return NULL;
    json_value_t *v = alloc_value(JSON_STRING);
    v->as.string = s;
    return v;
}

static json_value_t *parse_number(parser_t *p) {
    size_t start = p->pos;
    if (p->src[p->pos] == '-') p->pos++;
    while (isdigit((unsigned char) p->src[p->pos])) p->pos++;
    if (p->src[p->pos] == '.') {
        p->pos++;
        while (isdigit((unsigned char) p->src[p->pos])) p->pos++;
    }
    if (p->src[p->pos] == 'e' || p->src[p->pos] == 'E') {
        p->pos++;
        if (p->src[p->pos] == '+' || p->src[p->pos] == '-') p->pos++;
        while (isdigit((unsigned char) p->src[p->pos])) p->pos++;
    }
    if (p->pos == start) {
        set_err(p, "invalid number");
        return NULL;
    }
    char *numstr = strndup(p->src + start, p->pos - start);
    json_value_t *v = alloc_value(JSON_NUMBER);
    v->as.number = strtod(numstr, NULL);
    free(numstr);
    return v;
}

static bool match_literal(parser_t *p, const char *lit) {
    size_t len = strlen(lit);
    if (strncmp(p->src + p->pos, lit, len) == 0) {
        p->pos += len;
        return true;
    }
    return false;
}

static json_value_t *parse_object(parser_t *p) {
    p->pos++; /* { */
    json_value_t *v = alloc_value(JSON_OBJECT);
    skip_ws(p);
    if (p->src[p->pos] == '}') {
        p->pos++;
        return v;
    }
    while (true) {
        skip_ws(p);
        char *key = parse_string_raw(p);
        if (!key) {
            json_free(v);
            return NULL;
        }
        skip_ws(p);
        if (p->src[p->pos] != ':') {
            set_err(p, "expected ':'");
            free(key);
            json_free(v);
            return NULL;
        }
        p->pos++;
        skip_ws(p);
        json_value_t *val = parse_value(p);
        if (!val) {
            free(key);
            json_free(v);
            return NULL;
        }
        v->as.object.keys = realloc(v->as.object.keys, sizeof(char *) * (v->as.object.count + 1));
        v->as.object.values = realloc(v->as.object.values, sizeof(json_value_t *) * (v->as.object.count + 1));
        v->as.object.keys[v->as.object.count] = key;
        v->as.object.values[v->as.object.count] = val;
        v->as.object.count++;
        skip_ws(p);
        if (p->src[p->pos] == ',') {
            p->pos++;
            continue;
        }
        if (p->src[p->pos] == '}') {
            p->pos++;
            break;
        }
        set_err(p, "expected ',' or '}'");
        json_free(v);
        return NULL;
    }
    return v;
}

static json_value_t *parse_array(parser_t *p) {
    p->pos++; /* [ */
    json_value_t *v = alloc_value(JSON_ARRAY);
    skip_ws(p);
    if (p->src[p->pos] == ']') {
        p->pos++;
        return v;
    }
    while (true) {
        skip_ws(p);
        json_value_t *val = parse_value(p);
        if (!val) {
            json_free(v);
            return NULL;
        }
        v->as.array.items = realloc(v->as.array.items, sizeof(json_value_t *) * (v->as.array.count + 1));
        v->as.array.items[v->as.array.count++] = val;
        skip_ws(p);
        if (p->src[p->pos] == ',') {
            p->pos++;
            continue;
        }
        if (p->src[p->pos] == ']') {
            p->pos++;
            break;
        }
        set_err(p, "expected ',' or ']'");
        json_free(v);
        return NULL;
    }
    return v;
}

static json_value_t *parse_value(parser_t *p) {
    skip_ws(p);
    char c = p->src[p->pos];
    if (c == '{') return parse_object(p);
    if (c == '[') return parse_array(p);
    if (c == '"') return parse_string(p);
    if (c == '-' || isdigit((unsigned char) c)) return parse_number(p);
    if (match_literal(p, "true")) {
        json_value_t *v = alloc_value(JSON_BOOL);
        v->as.boolean = true;
        return v;
    }
    if (match_literal(p, "false")) {
        json_value_t *v = alloc_value(JSON_BOOL);
        v->as.boolean = false;
        return v;
    }
    if (match_literal(p, "null")) {
        return alloc_value(JSON_NULL);
    }
    set_err(p, "unexpected token");
    return NULL;
}

json_value_t *json_parse(const char *text, char *err, size_t err_len) {
    parser_t p = {.src = text, .pos = 0, .err = err, .err_len = err_len, .failed = false};
    json_value_t *v = parse_value(&p);
    if (!v) return NULL;
    skip_ws(&p);
    if (p.src[p.pos] != '\0') {
        set_err(&p, "trailing data after JSON value");
        json_free(v);
        return NULL;
    }
    return v;
}

json_value_t *json_parse_file(const char *path, char *err, size_t err_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        if (err && err_len) snprintf(err, err_len, "cannot open %s: %s", path, strerror(errno));
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t) size + 1);
    size_t n = fread(buf, 1, (size_t) size, f);
    fclose(f);
    buf[n] = '\0';
    json_value_t *v = json_parse(buf, err, err_len);
    free(buf);
    return v;
}

void json_free(json_value_t *v) {
    if (!v) return;
    switch (v->type) {
        case JSON_STRING:
            free(v->as.string);
            break;
        case JSON_ARRAY:
            for (size_t i = 0; i < v->as.array.count; i++) json_free(v->as.array.items[i]);
            free(v->as.array.items);
            break;
        case JSON_OBJECT:
            for (size_t i = 0; i < v->as.object.count; i++) {
                free(v->as.object.keys[i]);
                json_free(v->as.object.values[i]);
            }
            free(v->as.object.keys);
            free(v->as.object.values);
            break;
        default:
            break;
    }
    free(v);
}

json_value_t *json_get(const json_value_t *obj, const char *key) {
    if (!obj || obj->type != JSON_OBJECT) return NULL;
    for (size_t i = 0; i < obj->as.object.count; i++) {
        if (strcmp(obj->as.object.keys[i], key) == 0) return obj->as.object.values[i];
    }
    return NULL;
}

const char *json_get_string(const json_value_t *obj, const char *key, const char *fallback) {
    json_value_t *v = json_get(obj, key);
    if (!v || v->type != JSON_STRING) return fallback;
    return v->as.string;
}

long json_get_int(const json_value_t *obj, const char *key, long fallback) {
    json_value_t *v = json_get(obj, key);
    if (!v || v->type != JSON_NUMBER) return fallback;
    return (long) v->as.number;
}

bool json_get_bool(const json_value_t *obj, const char *key, bool fallback) {
    json_value_t *v = json_get(obj, key);
    if (!v || v->type != JSON_BOOL) return fallback;
    return v->as.boolean;
}

json_value_t *json_new_object(void) {
    return alloc_value(JSON_OBJECT);
}

json_value_t *json_new_array(void) {
    return alloc_value(JSON_ARRAY);
}

void json_object_set(json_value_t *obj, const char *key, json_value_t *val) {
    for (size_t i = 0; i < obj->as.object.count; i++) {
        if (strcmp(obj->as.object.keys[i], key) == 0) {
            json_free(obj->as.object.values[i]);
            obj->as.object.values[i] = val;
            return;
        }
    }
    obj->as.object.keys = realloc(obj->as.object.keys, sizeof(char *) * (obj->as.object.count + 1));
    obj->as.object.values = realloc(obj->as.object.values, sizeof(json_value_t *) * (obj->as.object.count + 1));
    obj->as.object.keys[obj->as.object.count] = strdup(key);
    obj->as.object.values[obj->as.object.count] = val;
    obj->as.object.count++;
}

void json_object_set_string(json_value_t *obj, const char *key, const char *val) {
    json_value_t *v = alloc_value(JSON_STRING);
    v->as.string = strdup(val ? val : "");
    json_object_set(obj, key, v);
}

void json_object_set_int(json_value_t *obj, const char *key, long val) {
    json_value_t *v = alloc_value(JSON_NUMBER);
    v->as.number = (double) val;
    json_object_set(obj, key, v);
}

void json_object_set_bool(json_value_t *obj, const char *key, bool val) {
    json_value_t *v = alloc_value(JSON_BOOL);
    v->as.boolean = val;
    json_object_set(obj, key, v);
}

void json_array_push(json_value_t *arr, json_value_t *val) {
    arr->as.array.items = realloc(arr->as.array.items, sizeof(json_value_t *) * (arr->as.array.count + 1));
    arr->as.array.items[arr->as.array.count++] = val;
}

static void append(char **buf, size_t *len, size_t *cap, const char *s) {
    size_t n = strlen(s);
    if (*len + n + 1 >= *cap) {
        while (*len + n + 1 >= *cap) *cap *= 2;
        *buf = realloc(*buf, *cap);
    }
    memcpy(*buf + *len, s, n + 1);
    *len += n;
}

static void write_string_escaped(char **buf, size_t *len, size_t *cap, const char *s) {
    append(buf, len, cap, "\"");
    char tmp[3] = {0};
    for (const char *c = s; *c; c++) {
        if (*c == '"' || *c == '\\') {
            tmp[0] = '\\';
            tmp[1] = *c;
            tmp[2] = '\0';
            append(buf, len, cap, tmp);
        } else if (*c == '\n') {
            append(buf, len, cap, "\\n");
        } else {
            tmp[0] = *c;
            tmp[1] = '\0';
            append(buf, len, cap, tmp);
        }
    }
    append(buf, len, cap, "\"");
}

static void write_value(char **buf, size_t *len, size_t *cap, const json_value_t *v, bool pretty, int depth) {
    char num[64];
    char indent[64];
    int ind_n = pretty ? depth * 2 : 0;
    if (ind_n > 62) ind_n = 62;
    memset(indent, ' ', (size_t) ind_n);
    indent[ind_n] = '\0';

    switch (v->type) {
        case JSON_NULL:
            append(buf, len, cap, "null");
            break;
        case JSON_BOOL:
            append(buf, len, cap, v->as.boolean ? "true" : "false");
            break;
        case JSON_NUMBER:
            if (v->as.number == (long) v->as.number) {
                snprintf(num, sizeof(num), "%ld", (long) v->as.number);
            } else {
                snprintf(num, sizeof(num), "%g", v->as.number);
            }
            append(buf, len, cap, num);
            break;
        case JSON_STRING:
            write_string_escaped(buf, len, cap, v->as.string);
            break;
        case JSON_ARRAY:
            append(buf, len, cap, "[");
            for (size_t i = 0; i < v->as.array.count; i++) {
                if (pretty) append(buf, len, cap, "\n");
                if (pretty) {
                    char child_indent[66];
                    snprintf(child_indent, sizeof(child_indent), "%s  ", indent);
                    append(buf, len, cap, child_indent);
                }
                write_value(buf, len, cap, v->as.array.items[i], pretty, depth + 1);
                if (i + 1 < v->as.array.count) append(buf, len, cap, ",");
            }
            if (pretty && v->as.array.count > 0) {
                append(buf, len, cap, "\n");
                append(buf, len, cap, indent);
            }
            append(buf, len, cap, "]");
            break;
        case JSON_OBJECT:
            append(buf, len, cap, "{");
            for (size_t i = 0; i < v->as.object.count; i++) {
                if (pretty) append(buf, len, cap, "\n");
                if (pretty) {
                    char child_indent[66];
                    snprintf(child_indent, sizeof(child_indent), "%s  ", indent);
                    append(buf, len, cap, child_indent);
                }
                write_string_escaped(buf, len, cap, v->as.object.keys[i]);
                append(buf, len, cap, pretty ? ": " : ":");
                write_value(buf, len, cap, v->as.object.values[i], pretty, depth + 1);
                if (i + 1 < v->as.object.count) append(buf, len, cap, ",");
            }
            if (pretty && v->as.object.count > 0) {
                append(buf, len, cap, "\n");
                append(buf, len, cap, indent);
            }
            append(buf, len, cap, "}");
            break;
    }
}

char *json_to_string(const json_value_t *v, bool pretty) {
    size_t cap = 128, len = 0;
    char *buf = malloc(cap);
    buf[0] = '\0';
    write_value(&buf, &len, &cap, v, pretty, 0);
    if (pretty) append(&buf, &len, &cap, "\n");
    return buf;
}

int json_write_file(const json_value_t *v, const char *path) {
    char *s = json_to_string(v, true);
    FILE *f = fopen(path, "w");
    if (!f) {
        free(s);
        return -1;
    }
    fputs(s, f);
    fclose(f);
    free(s);
    return 0;
}
