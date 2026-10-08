/* tess_sign.c — Ed25519ph (streaming) detached signatures. */
#include "tess_internal.h"

#include <sodium/utils.h>

void tess_sign_begin(tess_sign_ctx *c) {
    memset(c, 0, sizeof *c);
    if (crypto_sign_init(&c->st) == 0) c->active = 1;
}

tess_status tess_sign_update(tess_sign_ctx *c, const uint8_t *m, size_t n) {
    if (c == NULL || !c->active) return TESS_ERR_INVALID_ARG;
    if (n == 0) return TESS_OK;
    if (crypto_sign_update(&c->st, m, n) != 0) return TESS_ERR_INTERNAL;
    return TESS_OK;
}

tess_status tess_sign_finish(tess_sign_ctx *c, const tess_key *secret,
                             uint8_t sig[crypto_sign_BYTES]) {
    unsigned long long siglen = 0;
    if (c == NULL || secret == NULL || sig == NULL || !c->active) {
        return TESS_ERR_INVALID_ARG;
    }
    if (!secret->is_secret || secret->is_locked) {
        c->active = 0;
        return TESS_ERR_INVALID_ARG;
    }
    /* the state is consumed by final_create, even on failure */
    if (crypto_sign_final_create(&c->st, sig, &siglen, secret->e_sk) != 0) {
        c->active = 0;
        return TESS_ERR_INTERNAL;
    }
    if (siglen != crypto_sign_BYTES) {
        c->active = 0;
        return TESS_ERR_INTERNAL;
    }
    c->active = 0;
    return TESS_OK;
}

void tess_verify_begin(tess_verify_ctx *c) {
    memset(c, 0, sizeof *c);
    if (crypto_sign_init(&c->st) == 0) c->active = 1;
}

tess_status tess_verify_update(tess_verify_ctx *c, const uint8_t *m,
                               size_t n) {
    if (c == NULL || !c->active) return TESS_ERR_INVALID_ARG;
    if (n == 0) return TESS_OK;
    if (crypto_sign_update(&c->st, m, n) != 0) return TESS_ERR_INTERNAL;
    return TESS_OK;
}

tess_status tess_verify_finish(tess_verify_ctx *c, const tess_key *pub,
                               const uint8_t sig[crypto_sign_BYTES]) {
    if (c == NULL || pub == NULL || sig == NULL || !c->active) {
        return TESS_ERR_INVALID_ARG;
    }
    if (crypto_sign_final_verify(&c->st, sig, pub->e_pk) != 0) {
        c->active = 0;
        return TESS_ERR_SIGNATURE;
    }
    c->active = 0;
    return TESS_OK;
}

/* ------------------------------------------------------------------ */
/* detached sign/verify over a buffer                                  */
/* ------------------------------------------------------------------ */

tess_status tess_sign(const uint8_t *msg, size_t msg_len, const tess_key *secret,
                      uint8_t sig[TESS_SIGNATURE_BYTES]) {
    tess_sign_ctx c;
    tess_status st;

    if ((msg == NULL && msg_len > 0) || secret == NULL || sig == NULL) {
        return TESS_ERR_INVALID_ARG;
    }
    /* Fail fast: signing requires an unlocked secret key */
    if (!secret->is_secret || secret->is_locked) {
        return TESS_ERR_INVALID_ARG;
    }
    tess_sign_begin(&c);
    st = tess_sign_update(&c, msg, msg_len);
    if (st != TESS_OK) return st;
    return tess_sign_finish(&c, secret, sig);
}

tess_status tess_verify(const uint8_t *msg, size_t msg_len,
                        const tess_key *public_key,
                        const uint8_t sig[TESS_SIGNATURE_BYTES]) {
    tess_verify_ctx c;
    tess_status st;

    if ((msg == NULL && msg_len > 0) || public_key == NULL || sig == NULL) {
        return TESS_ERR_INVALID_ARG;
    }
    /* Fail fast: verification requires a public key */
    if (public_key->is_secret) {
        return TESS_ERR_INVALID_ARG;
    }
    tess_verify_begin(&c);
    st = tess_verify_update(&c, msg, msg_len);
    if (st != TESS_OK) return st;
    return tess_verify_finish(&c, public_key, sig);
}

/* ------------------------------------------------------------------ */
/* detached sign/verify over a file (streaming, constant memory)       */
/* ------------------------------------------------------------------ */

#define IO_CHUNK (256u * 1024u)

static tess_status stream_file(const char *path,
                               tess_status (*fn)(void *, const uint8_t *,
                                                 size_t), void *ctx) {
    FILE *f;
    uint8_t buf[IO_CHUNK];
    size_t n;
    tess_status st = TESS_OK;

    f = fopen(path, "rb");
    if (f == NULL) return TESS_ERR_IO;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        st = fn(ctx, buf, n);
        if (st != TESS_OK) break;
    }
    if (st == TESS_OK && ferror(f)) st = TESS_ERR_IO;
    fclose(f);
    sodium_memzero(buf, sizeof buf);
    return st;
}

static tess_status sign_feed(void *ctx, const uint8_t *m, size_t n) {
    return tess_sign_update((tess_sign_ctx *)ctx, m, n);
}

static tess_status verify_feed(void *ctx, const uint8_t *m, size_t n) {
    return tess_verify_update((tess_verify_ctx *)ctx, m, n);
}

/* Size of `path` at open time; used to detect the file changing while we
 * stream it (signing/verifying inconsistent bytes would be worse than an
 * I/O error). */
static tess_status path_size(const char *path, uint64_t *out) {
    FILE *f = fopen(path, "rb");
    tess_status st;
    if (f == NULL) return TESS_ERR_IO;
    st = tess_file_size(f, out);
    fclose(f);
    return st;
}

tess_status tess_sign_file(const char *path, const tess_key *secret,
                           uint8_t sig[TESS_SIGNATURE_BYTES]) {
    tess_sign_ctx c;
    tess_status st;
    uint64_t sz_before = 0, sz_after = 0;

    if (path == NULL || secret == NULL || sig == NULL) {
        return TESS_ERR_INVALID_ARG;
    }
    if (!secret->is_secret || secret->is_locked) return TESS_ERR_INVALID_ARG;
    if (path_size(path, &sz_before) != TESS_OK) return TESS_ERR_IO;
    tess_sign_begin(&c);
    st = stream_file(path, sign_feed, &c);
    if (st != TESS_OK) return st;
    if (path_size(path, &sz_after) != TESS_OK || sz_after != sz_before) {
        return TESS_ERR_IO;
    }
    return tess_sign_finish(&c, secret, sig);
}

tess_status tess_verify_file(const char *path, const tess_key *public_key,
                             const uint8_t sig[TESS_SIGNATURE_BYTES]) {
    tess_verify_ctx c;
    tess_status st;
    uint64_t sz_before = 0, sz_after = 0;

    if (path == NULL || public_key == NULL || sig == NULL) {
        return TESS_ERR_INVALID_ARG;
    }
    if (path_size(path, &sz_before) != TESS_OK) return TESS_ERR_IO;
    tess_verify_begin(&c);
    st = stream_file(path, verify_feed, &c);
    if (st != TESS_OK) return st;
    if (path_size(path, &sz_after) != TESS_OK || sz_after != sz_before) {
        return TESS_ERR_IO;
    }
    return tess_verify_finish(&c, public_key, sig);
}
