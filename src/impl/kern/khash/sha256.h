#ifndef ROOTVIEW_KHASH_SHA256_H
#define ROOTVIEW_KHASH_SHA256_H

#include <stddef.h>
#include <stdint.h>

/* FIPS 180-4 SHA-256, single file, no dependencies. public domain: written
 * for rootview from the spec, so the build image's gcc is all it needs. */

#define SHA256_LEN 32

typedef struct {
    uint32_t h[8];
    uint64_t bits;
    unsigned char buf[64];
    size_t used;
} sha256_t;

void sha256_init(sha256_t *s);
void sha256_update(sha256_t *s, const void *data, size_t len);
void sha256_final(sha256_t *s, uint8_t out[SHA256_LEN]);

/* the three above in one call */
void sha256(const void *data, size_t len, uint8_t out[SHA256_LEN]);

#endif
