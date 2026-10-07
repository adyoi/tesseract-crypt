/* tess_header.c — serialization, parsing and validation of the 264-byte
 * message header (magic "TSCR").  See docs/format.html for the layout. */
#include "tess_internal.h"

#include <sodium/utils.h>

void tess_header_init(tess_header *h) {
    memset(h, 0, sizeof *h);
    h->version = TESS_VERSION;
    h->suite = TESS_SUITE_1;
    h->chunk_size = TESS_DEFAULT_CHUNK;
    h->pt_len = UINT64_MAX;
    h->argon_ops = TESS_ARGON_DEF_OPS;
    h->argon_mem = TESS_ARGON_DEF_MEM;
}

tess_status tess_header_serialize(const tess_header *h,
                                  uint8_t out[TESS_HEADER_BYTES]) {
    if (h == NULL || out == NULL) return TESS_ERR_INVALID_ARG;

    memset(out, 0, TESS_HEADER_BYTES);
    memcpy(out + TESS_OFF_MAGIC, TESS_MAGIC, TESS_MAGIC_LEN);
    out[TESS_OFF_VERSION] = h->version;
    out[TESS_OFF_SUITE] = h->suite;
    out[TESS_OFF_MODE] = h->mode;
    out[TESS_OFF_FLAGS] = h->flags;
    memcpy(out + TESS_OFF_EPH_PK, h->eph_pk, sizeof h->eph_pk);
    memcpy(out + TESS_OFF_RECIPIENT_PK, h->recipient_pk, sizeof h->recipient_pk);
    memcpy(out + TESS_OFF_SENDER_X_PK, h->sender_x_pk, sizeof h->sender_x_pk);
    memcpy(out + TESS_OFF_SENDER_ED_PK, h->sender_ed_pk, sizeof h->sender_ed_pk);
    memcpy(out + TESS_OFF_SIGNATURE, h->signature, sizeof h->signature);
    memcpy(out + TESS_OFF_SALT, h->salt, sizeof h->salt);
    tess_wr_u32(out + TESS_OFF_ARGON_OPS, h->argon_ops);
    tess_wr_u64(out + TESS_OFF_ARGON_MEM, h->argon_mem);
    memcpy(out + TESS_OFF_NONCE, h->nonce, sizeof h->nonce);
    tess_wr_u32(out + TESS_OFF_CHUNK, h->chunk_size);
    tess_wr_u64(out + TESS_OFF_PT_LEN, h->pt_len);
    return TESS_OK;
}

tess_status tess_header_validate(const tess_header *h) {
    if (h == NULL) return TESS_ERR_INVALID_ARG;
    if (h->version != TESS_VERSION) return TESS_ERR_UNSUPPORTED;
    if (h->suite != TESS_SUITE_1) return TESS_ERR_UNSUPPORTED;
    if (h->mode != TESS_MODE_PUBLICKEY && h->mode != TESS_MODE_PASSPHRASE) {
        return TESS_ERR_FORMAT;
    }
    if ((h->flags & ~(unsigned)TESS_FLAG_SIGNED) != 0) return TESS_ERR_FORMAT;
    if (h->chunk_size < TESS_MIN_CHUNK || h->chunk_size > TESS_MAX_CHUNK) {
        return TESS_ERR_FORMAT;
    }
    if (h->mode == TESS_MODE_PASSPHRASE) {
        if (h->argon_ops == 0 || h->argon_ops > TESS_ARGON_MAX_OPS) {
            return TESS_ERR_FORMAT;
        }
        if (h->argon_mem < (64ull * 1024ull) ||
            h->argon_mem > TESS_ARGON_MAX_MEM) {
            return TESS_ERR_FORMAT;
        }
        if (h->argon_mem > SIZE_MAX) return TESS_ERR_FORMAT;
    }
    if ((h->flags & TESS_FLAG_SIGNED) != 0) {
        /* a non-zero signer key must be present; all-zero => malformed */
        uint8_t acc = 0;
        size_t i;
        for (i = 0; i < sizeof h->sender_ed_pk; i++) {
            acc |= h->sender_ed_pk[i];
        }
        if (acc == 0) return TESS_ERR_FORMAT;
    }
    return TESS_OK;
}

tess_status tess_header_parse(const uint8_t in[TESS_HEADER_BYTES],
                              tess_header *h) {
    tess_status st;

    if (in == NULL || h == NULL) return TESS_ERR_INVALID_ARG;
    if (memcmp(in + TESS_OFF_MAGIC, TESS_MAGIC, TESS_MAGIC_LEN) != 0) {
        return TESS_ERR_FORMAT;
    }

    tess_header_init(h);
    h->version = in[TESS_OFF_VERSION];
    h->suite = in[TESS_OFF_SUITE];
    h->mode = in[TESS_OFF_MODE];
    h->flags = in[TESS_OFF_FLAGS];
    memcpy(h->eph_pk, in + TESS_OFF_EPH_PK, sizeof h->eph_pk);
    memcpy(h->recipient_pk, in + TESS_OFF_RECIPIENT_PK, sizeof h->recipient_pk);
    memcpy(h->sender_x_pk, in + TESS_OFF_SENDER_X_PK, sizeof h->sender_x_pk);
    memcpy(h->sender_ed_pk, in + TESS_OFF_SENDER_ED_PK, sizeof h->sender_ed_pk);
    memcpy(h->signature, in + TESS_OFF_SIGNATURE, sizeof h->signature);
    memcpy(h->salt, in + TESS_OFF_SALT, sizeof h->salt);
    h->argon_ops = tess_rd_u32(in + TESS_OFF_ARGON_OPS);
    h->argon_mem = tess_rd_u64(in + TESS_OFF_ARGON_MEM);
    memcpy(h->nonce, in + TESS_OFF_NONCE, sizeof h->nonce);
    h->chunk_size = tess_rd_u32(in + TESS_OFF_CHUNK);
    h->pt_len = tess_rd_u64(in + TESS_OFF_PT_LEN);

    st = tess_header_validate(h);
    if (st != TESS_OK) return st;
    return TESS_OK;
}
