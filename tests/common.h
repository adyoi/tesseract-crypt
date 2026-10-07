/* common test helpers — not installed, test-local */
#ifndef TESS_TEST_COMMON_H
#define TESS_TEST_COMMON_H

#include "tesseract/tesseract.h"

#include <sodium.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                        \
        }                                                                    \
    } while (0)

#define CHECK_ST(st, expected)                                               \
    do {                                                                     \
        tess_status got__ = (st);                                            \
        tess_status want__ = (expected);                                     \
        if (got__ != want__) {                                               \
            fprintf(stderr, "FAIL %s:%d: got '%s', want '%s'\n", __FILE__,   \
                    __LINE__, tess_strerror(got__), tess_strerror(want__));  \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static inline int bytes_eq(const uint8_t *a, size_t alen, const uint8_t *b,
                           size_t blen) {
    if (alen != blen) return 0;
    return alen == 0 || memcmp(a, b, alen) == 0;
}

static inline uint8_t *fill_pattern(size_t n, uint8_t seed) {
    uint8_t *p = (uint8_t *)malloc(n ? n : 1);
    size_t i;
    for (i = 0; i < n; i++) p[i] = (uint8_t)(seed + (i * 31u + (i >> 8)));
    return p;
}

#endif
