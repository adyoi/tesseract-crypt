/* tess_util.c — endian helpers, allocation, armor, file I/O helpers. */
#ifdef _WIN32
#include <io.h>
#else
/* Large-file seeks (fseeko/ftello) and POSIX file helpers. */
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "tess_internal.h"

#include <errno.h>
#include <sodium/utils.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

/* POSIX rename() overwrites atomically; Windows' rename() does not.
 *
 * Never fall back to remove(to)+rename(from,to): if the second rename then
 * fails (permissions, EXDEV), the destination is destroyed for nothing. */
int tess_replace_file(const char *from, const char *to) {
#ifdef _WIN32
    if (MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING) != 0) return 0;
#endif
    if (rename(from, to) == 0) return 0;
    return -1;
}

/* ------------------------------------------------------------------ */
/* endian helpers                                                      */
/* ------------------------------------------------------------------ */

void tess_wr_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

void tess_wr_u64(uint8_t *p, uint64_t v) {
    tess_wr_u32(p, (uint32_t)(v & 0xffffffffu));
    tess_wr_u32(p + 4, (uint32_t)(v >> 32));
}

uint32_t tess_rd_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

uint64_t tess_rd_u64(const uint8_t *p) {
    uint64_t lo = tess_rd_u32(p);
    uint64_t hi = tess_rd_u32(p + 4);
    return lo | (hi << 32);
}

/* ------------------------------------------------------------------ */
/* allocation                                                          */
/* ------------------------------------------------------------------ */

tess_status tess_alloc(size_t n, void **out) {
    void *p;
    if (out == NULL) return TESS_ERR_INVALID_ARG;
    *out = NULL;
    p = malloc(n == 0 ? 1 : n);
    if (p == NULL) return TESS_ERR_NOMEM;
    *out = p;
    return TESS_OK;
}

void tess_secure_free(void *p, size_t n) {
    if (p == NULL) return;
    sodium_memzero(p, n);
    free(p);
}

void tess_free(void *ptr) { free(ptr); }

/* ------------------------------------------------------------------ */
/* armor                                                               */
/* ------------------------------------------------------------------ */

#define ARMOR_LINE 64
#define ARMOR_WIDTH ((size_t)((ARMOR_LINE * 4) / 3 + 4))

int tess_is_armored(const uint8_t *data, size_t len) {
    static const char *needle = "-----BEGIN ";
    size_t i, n = strlen(needle);
    if (data == NULL || len < n) return 0;
    for (i = 0; i + n <= len && i < 64; i++) {
        if (memcmp(data + i, needle, n) == 0) return 1;
    }
    return 0;
}

tess_status tess_armor(const uint8_t *in, size_t len, const char *label,
                       char **out) {
    char *buf = NULL;
    size_t b64len, need, pos = 0, linelen;
    const size_t label_len = label ? strlen(label) : 0;

    if (in == NULL || out == NULL || len > (SIZE_MAX / 2)) {
        return TESS_ERR_INVALID_ARG;
    }
    *out = NULL;

    b64len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    /* header + body (wrapped) + footer + NUL; generous upper bound */
    if (b64len > SIZE_MAX / 2 ||
        label_len > SIZE_MAX / 4 ||
        40 + 2 * label_len + b64len + (b64len / ARMOR_LINE) + 8 > SIZE_MAX) {
        return TESS_ERR_NOMEM;
    }
    need = 40 + 2 * label_len + b64len + (b64len / ARMOR_LINE) + 8;
    buf = (char *)malloc(need);
    if (buf == NULL) return TESS_ERR_NOMEM;

    pos += (size_t)snprintf(buf + pos, need - pos, "-----BEGIN %s-----\n",
                            label_len ? label : "TESSERACT DATA");

    {
        char *b64 = (char *)malloc(b64len);
        if (b64 == NULL) {
            free(buf);
            return TESS_ERR_NOMEM;
        }
        sodium_bin2base64(b64, b64len, in, len, sodium_base64_VARIANT_ORIGINAL);
        /* strip the terminating NUL, wrap manually */
        linelen = strlen(b64);
        {
            size_t i;
            for (i = 0; i < linelen; i += ARMOR_LINE) {
                size_t chunk = linelen - i;
                if (chunk > ARMOR_LINE) chunk = ARMOR_LINE;
                memcpy(buf + pos, b64 + i, chunk);
                pos += chunk;
                buf[pos++] = '\n';
            }
        }
        sodium_memzero(b64, b64len);
        free(b64);
    }

    pos += (size_t)snprintf(buf + pos, need - pos, "-----END %s-----\n",
                            label_len ? label : "TESSERACT DATA");
    buf[pos] = '\0';
    *out = buf;
    return TESS_OK;
}

tess_status tess_dearmor(const char *text, uint8_t **out, size_t *out_len) {
    const char *begin, *end, *p;
    size_t max, n = 0;
    char *b64;
    uint8_t *raw;
    size_t raw_len = 0;

    if (text == NULL || out == NULL || out_len == NULL) {
        return TESS_ERR_INVALID_ARG;
    }
    *out = NULL;
    *out_len = 0;

    begin = strstr(text, "-----BEGIN ");
    if (begin == NULL) return TESS_ERR_FORMAT;
    begin = strchr(begin, '\n');
    if (begin == NULL) return TESS_ERR_FORMAT;
    begin++;

    end = strstr(begin, "-----END ");
    if (end == NULL) return TESS_ERR_FORMAT;

    max = (size_t)(end - begin) + 2;
    b64 = (char *)malloc(max);
    if (b64 == NULL) return TESS_ERR_NOMEM;

    for (p = begin; p < end; p++) {
        char ch = *p;
        if (ch == '\n' || ch == '\r' || ch == ' ' || ch == '\t') continue;
        b64[n++] = ch;
    }
    b64[n] = '\0';

    raw = (uint8_t *)malloc(n + 1);
    if (raw == NULL) {
        sodium_memzero(b64, n + 1);
        free(b64);
        return TESS_ERR_NOMEM;
    }
    if (sodium_base642bin(raw, n + 1, b64, n, NULL, &raw_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0 &&
        sodium_base642bin(raw, n + 1, b64, n, NULL, &raw_len, NULL,
                          sodium_base64_VARIANT_URLSAFE) != 0) {
        sodium_memzero(raw, n + 1);
        free(raw);
        free(b64);
        return TESS_ERR_FORMAT;
    }
    sodium_memzero(b64, n + 1);
    free(b64);
    *out = raw;
    *out_len = raw_len;
    return TESS_OK;
}

/* ------------------------------------------------------------------ */
/* file helpers                                                        */
/* ------------------------------------------------------------------ */

#ifdef _WIN32
#define TESS_FSEEK64(f, off, whence) _fseeki64((f), (off), (whence))
#define TESS_FTELL64(f) _ftelli64((f))
#else
#define TESS_FSEEK64(f, off, whence) fseeko((f), (off), (whence))
#define TESS_FTELL64(f) ftello((f))
#endif

/* 64-bit file size; leaves the stream positioned at the start. */
tess_status tess_file_size(FILE *f, uint64_t *out) {
    int64_t sz;
    if (f == NULL || out == NULL) return TESS_ERR_INVALID_ARG;
    if (TESS_FSEEK64(f, 0, SEEK_END) != 0) return TESS_ERR_IO;
    sz = TESS_FTELL64(f);
    if (sz < 0) return TESS_ERR_IO;
    if (TESS_FSEEK64(f, 0, SEEK_SET) != 0) return TESS_ERR_IO;
    *out = (uint64_t)sz;
    return TESS_OK;
}

/* Flush file data to stable storage before publishing (rename/close). */
tess_status tess_sync_file(FILE *f) {
    if (f == NULL) return TESS_ERR_INVALID_ARG;
    if (fflush(f) != 0) return TESS_ERR_IO;
#ifdef _WIN32
    if (_commit(_fileno(f)) != 0) return TESS_ERR_IO;
#else
    if (fsync(fileno(f)) != 0) return TESS_ERR_IO;
#endif
    return TESS_OK;
}

/* Restrict a file we create to owner-only access (keys, plaintexts,
 * ciphertext .part files). No-op on Windows: ACLs inherit from the
 * directory instead, so Unix-style mode bits are best-effort there. */
void tess_restrict_file(FILE *f) {
#ifdef _WIN32
    (void)f;
#else
    if (f != NULL) (void)fchmod(fileno(f), S_IRUSR | S_IWUSR);
#endif
}

tess_status tess_read_file(const char *path, uint8_t **buf, size_t *len) {
    FILE *f;
    uint64_t sz = 0;
    uint8_t *p;
    size_t got;

    if (path == NULL || buf == NULL || len == NULL) return TESS_ERR_INVALID_ARG;
    *buf = NULL;
    *len = 0;

    f = fopen(path, "rb");
    if (f == NULL) return TESS_ERR_IO;
    if (tess_file_size(f, &sz) != TESS_OK) {
        fclose(f);
        return TESS_ERR_IO;
    }
    if (sz > (uint64_t)(SIZE_MAX - 1)) { /* file too large for this platform */
        fclose(f);
        return TESS_ERR_NOMEM;
    }
    /* Check for overflow in sz + 1 */
    if (sz == SIZE_MAX) {
        fclose(f);
        return TESS_ERR_NOMEM;
    }
    p = (uint8_t *)malloc((size_t)sz + 1);
    if (p == NULL) {
        fclose(f);
        return TESS_ERR_NOMEM;
    }
    got = fread(p, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) {
        free(p);
        return TESS_ERR_IO;
    }
    p[got] = 0; /* convenient for text inputs */
    *buf = p;
    *len = got;
    return TESS_OK;
}

static int make_part_path(const char *path, char *part, size_t cap) {
    int n = snprintf(part, cap, "%s.part", path);
    if (n < 0 || (size_t)n >= cap) return -1;
    return 0;
}

tess_status tess_write_file_atomic(const char *path, const uint8_t *buf,
                                   size_t len) {
    char part[4096];
    FILE *f;
    size_t wrote;

    if (make_part_path(path, part, sizeof part) != 0) {
        return TESS_ERR_INVALID_ARG;
    }
    f = fopen(part, "wb");
    if (f == NULL) return TESS_ERR_IO;
    tess_restrict_file(f);
    wrote = len ? fwrite(buf, 1, len, f) : 0;
    if (wrote != len || tess_sync_file(f) != TESS_OK) {
        fclose(f);
        remove(part);
        return TESS_ERR_IO;
    }
    fclose(f);
    if (tess_replace_file(part, path) != 0) {
        remove(part);
        return TESS_ERR_IO;
    }
    return TESS_OK;
}
