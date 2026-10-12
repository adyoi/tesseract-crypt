/* tess_seal.c — key schedule, seal/open for buffers and files. */
#include "tess_internal.h"

#include <sodium.h>
#include <sodium/utils.h>

/* ------------------------------------------------------------------ */
/* options                                                             */
/* ------------------------------------------------------------------ */

void tess_seal_options_init(tess_seal_options *o) {
    if (o) memset(o, 0, sizeof *o);
}

void tess_open_options_init(tess_open_options *o) {
    if (o) memset(o, 0, sizeof *o);
}

void tess_seal_file_options_init(tess_seal_file_options *o) {
    if (o) memset(o, 0, sizeof *o);
}

void tess_open_file_options_init(tess_open_file_options *o) {
    if (o) memset(o, 0, sizeof *o);
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static int all_zero(const uint8_t *p, size_t n) {
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

void tess_master_free(tess_master *m) {
    if (m == NULL) return;
    sodium_memzero(m, sizeof *m);
}

/* mode 1: master = BLAKE2b-256(key = X25519(eph_sk, recipient_pk),
 *             in = dh_stat || salt || "tesseract-kdf-v1")                  */
tess_status tess_derive_master_pk(
    const uint8_t eph_sk[crypto_scalarmult_BYTES],
    const uint8_t recipient_pk[crypto_scalarmult_BYTES], const uint8_t *sender_sk,
    const uint8_t *salt, tess_master *out) {
    uint8_t dh_eph[crypto_scalarmult_BYTES];
    uint8_t dh_stat[crypto_scalarmult_BYTES];
    uint8_t in[32 + 16 + sizeof(TESS_KDF_CONTEXT) - 1];
    tess_status rc = TESS_OK;

    if (eph_sk == NULL || recipient_pk == NULL || salt == NULL || out == NULL) {
        return TESS_ERR_INVALID_ARG;
    }

    if (crypto_scalarmult(dh_eph, eph_sk, recipient_pk) != 0) {
        return TESS_ERR_CRYPTO;
    }
    if (sender_sk != NULL) {
        if (crypto_scalarmult(dh_stat, sender_sk, recipient_pk) != 0) {
            rc = TESS_ERR_CRYPTO;
            goto out;
        }
    } else {
        memset(dh_stat, 0, sizeof dh_stat); /* anonymous sender */
    }

    memcpy(in, dh_stat, 32);
    memcpy(in + 32, salt, 16);
    memcpy(in + 48, TESS_KDF_CONTEXT, sizeof(TESS_KDF_CONTEXT) - 1);

    if (crypto_generichash(out->key, sizeof out->key, in, sizeof in, dh_eph,
                           sizeof dh_eph) != 0) {
        rc = TESS_ERR_INTERNAL;
    }

out:
    sodium_memzero(dh_eph, sizeof dh_eph);
    sodium_memzero(dh_stat, sizeof dh_stat);
    sodium_memzero(in, sizeof in);
    return rc;
}

/* decryption side of the mode-1 schedule */
tess_status tess_derive_master_open(
    const tess_header *h, const uint8_t recipient_sk[crypto_scalarmult_BYTES],
    tess_master *out) {
    uint8_t dh_eph[crypto_scalarmult_BYTES];
    uint8_t dh_stat[crypto_scalarmult_BYTES];
    uint8_t in[32 + 16 + sizeof(TESS_KDF_CONTEXT) - 1];
    tess_status rc = TESS_OK;

    if (h == NULL || recipient_sk == NULL || out == NULL) {
        return TESS_ERR_INVALID_ARG;
    }
    if (h->mode == TESS_MODE_PASSPHRASE) return TESS_ERR_INVALID_ARG;
    if (all_zero(h->eph_pk, sizeof h->eph_pk)) return TESS_ERR_FORMAT;

    if (crypto_scalarmult(dh_eph, recipient_sk, h->eph_pk) != 0) {
        return TESS_ERR_CRYPTO;
    }
    if (!all_zero(h->sender_x_pk, sizeof h->sender_x_pk)) {
        /* static DH between recipient and the sender key in the header */
        if (crypto_scalarmult(dh_stat, recipient_sk, h->sender_x_pk) != 0) {
            rc = TESS_ERR_CRYPTO;
            goto out;
        }
    } else {
        memset(dh_stat, 0, sizeof dh_stat); /* anonymous sender */
    }

    memcpy(in, dh_stat, 32);
    memcpy(in + 32, h->salt, 16);
    memcpy(in + 48, TESS_KDF_CONTEXT, sizeof(TESS_KDF_CONTEXT) - 1);

    if (crypto_generichash(out->key, sizeof out->key, in, sizeof in, dh_eph,
                           sizeof dh_eph) != 0) {
        rc = TESS_ERR_INTERNAL;
    }

out:
    sodium_memzero(dh_eph, sizeof dh_eph);
    sodium_memzero(dh_stat, sizeof dh_stat);
    sodium_memzero(in, sizeof in);
    return rc;
}

tess_status tess_derive_master_pass(const char *passphrase,
                                    const uint8_t salt[16], uint32_t ops,
                                    uint64_t mem, tess_master *out) {
    if (passphrase == NULL || salt == NULL || out == NULL) {
        return TESS_ERR_INVALID_ARG;
    }
    if (ops < 1 || ops > TESS_ARGON_MAX_OPS) return TESS_ERR_FORMAT;
    if (mem < (64ull * 1024ull) || mem > TESS_ARGON_MAX_MEM) {
        return TESS_ERR_FORMAT;
    }
    if (crypto_pwhash(out->key, sizeof out->key, passphrase,
                      strlen(passphrase), salt, ops, mem,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return TESS_ERR_PASSPHRASE;
    }
    return TESS_OK;
}

/* ------------------------------------------------------------------ */
/* per-chunk keys                                                      */
/* ------------------------------------------------------------------ */

void tess_chunk_nonce(
    const uint8_t base[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES],
    uint64_t index,
    uint8_t out[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]) {
    int j;
    memcpy(out, base, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    for (j = 0; j < 8; j++) {
        out[16 + j] ^= (uint8_t)((index >> (56 - 8 * j)) & 0xffu);
    }
}

void tess_chunk_aad(const uint8_t header[TESS_HEADER_BYTES], uint64_t index,
                    int is_final, uint8_t out[TESS_HEADER_BYTES + 9]) {
    int j;
    memcpy(out, header, TESS_HEADER_BYTES);
    for (j = 0; j < 8; j++) {
        out[TESS_HEADER_BYTES + j] =
            (uint8_t)((index >> (56 - 8 * j)) & 0xffu);
    }
    out[TESS_HEADER_BYTES + 8] = is_final ? 1u : 0u;
}

tess_status tess_chunk_key(const tess_master *m, uint64_t index,
                           uint8_t out[crypto_kdf_KEYBYTES]) {
    if (m == NULL || out == NULL) return TESS_ERR_INVALID_ARG;
    if (crypto_kdf_derive_from_key(out, crypto_kdf_KEYBYTES, index + 1,
                                   TESS_CHUNK_CONTEXT, m->key) != 0) {
        return TESS_ERR_INTERNAL;
    }
    return TESS_OK;
}

/* ------------------------------------------------------------------ */
/* seal — shared machinery                                             */
/* ------------------------------------------------------------------ */

static uint32_t pick_chunk(uint32_t requested) {
    if (requested == 0) return TESS_DEFAULT_CHUNK;
    if (requested < TESS_MIN_CHUNK) return TESS_MIN_CHUNK;
    if (requested > TESS_MAX_CHUNK) return TESS_MAX_CHUNK;
    return requested;
}

/* on-wire size of the recipient segment (0 unless multi-recipient v2).
 * Returns 0 for invalid counts; seal_prepare() rejects those inputs. */
static size_t seal_blocks_len(const tess_seal_options *opt) {
    if (opt == NULL || opt->recipients == NULL) return 0;
    if (opt->recipient_count == 0 ||
        opt->recipient_count > TESS_MAX_RECIPIENTS) {
        return 0;
    }
    return (size_t)opt->recipient_count * TESS_RECIPIENT_BLOCK_BYTES;
}

/* Build the header for sealing and derive the master key.
 * For file sealing, `pt`/`pt_len` describe the data to be signed (the first
 * bytes are enough for the caller-provided signature callback alternative;
 * the buffer seal signs the whole buffer directly).  `blocks` receives the
 * per-recipient key blocks of a format-v2 message (NULL for v1). */
static tess_status seal_prepare(const uint8_t *pt, size_t pt_len,
                                const uint8_t *signature_or_null,
                                const tess_seal_options *opt,
                                uint8_t hdr_raw[TESS_HEADER_BYTES],
                                uint8_t *blocks, tess_header *h,
                                tess_master *master) {
    tess_status st;
    uint8_t eph_sk[crypto_box_SECRETKEYBYTES];
    const uint8_t *sender_sk =
        opt ? (opt->sender_secret ? opt->sender_secret->x_sk : NULL) : NULL;
    int multi = 0;
    int have_eph = 0;

    if (opt == NULL) return TESS_ERR_INVALID_ARG;
    memset(eph_sk, 0, sizeof eph_sk);

    if (opt->recipient_public != NULL && opt->passphrase != NULL) {
        return TESS_ERR_INVALID_ARG; /* mode must be unambiguous */
    }
    if (opt->recipients != NULL) {
        size_t i;
        if (opt->recipient_public != NULL || opt->passphrase != NULL) {
            return TESS_ERR_INVALID_ARG; /* mode must be unambiguous */
        }
        if (opt->recipient_count == 0 ||
            opt->recipient_count > TESS_MAX_RECIPIENTS) {
            return TESS_ERR_INVALID_ARG;
        }
        for (i = 0; i < opt->recipient_count; i++) {
            const tess_key *rk = opt->recipients[i];
            if (rk == NULL || all_zero(rk->x_pk, sizeof rk->x_pk)) {
                return TESS_ERR_INVALID_ARG;
            }
        }
    }

    tess_header_init(h);
    h->chunk_size = pick_chunk(opt->chunk_size);
    h->pt_len = pt_len;

    if (opt->recipient_public != NULL || opt->recipients != NULL) {
        multi = (opt->recipients != NULL);
        h->mode = TESS_MODE_PUBLICKEY;
        if (multi) {
            h->version = TESS_VERSION_MULTI;
            h->recip_count = (uint32_t)opt->recipient_count;
        }
        randombytes_buf(h->salt, sizeof h->salt);
        randombytes_buf(h->nonce, sizeof h->nonce);
        if (!multi) {
            memcpy(h->recipient_pk, opt->recipient_public->x_pk,
                   sizeof h->recipient_pk);
        }

        randombytes_buf(eph_sk, sizeof eph_sk);
        have_eph = 1;
        if (crypto_scalarmult_base(h->eph_pk, eph_sk) != 0) {
            sodium_memzero(eph_sk, sizeof eph_sk);
            have_eph = 0;
            return TESS_ERR_INTERNAL;
        }
        if (multi) {
            /* v2: a fresh random data key protects the payload; it is
             * wrapped once per recipient below (domain-separated by the
             * recipient key itself). */
            randombytes_buf(master->key, sizeof master->key);
        } else {
            st = tess_derive_master_pk(eph_sk, opt->recipient_public->x_pk,
                                       sender_sk, h->salt, master);
            if (st != TESS_OK) {
                sodium_memzero(eph_sk, sizeof eph_sk);
                have_eph = 0;
                return st;
            }
        }

        if (opt->sender_secret != NULL) {
            memcpy(h->sender_x_pk, opt->sender_secret->x_pk,
                   sizeof h->sender_x_pk);
        }
    } else {
        /* passphrase mode */
        if (opt->passphrase == NULL || opt->passphrase[0] == '\0') {
            return TESS_ERR_INVALID_ARG;
        }
        h->mode = TESS_MODE_PASSPHRASE;
        randombytes_buf(h->salt, sizeof h->salt);
        randombytes_buf(h->nonce, sizeof h->nonce);
        h->argon_ops = TESS_ARGON_DEF_OPS;
        h->argon_mem = TESS_ARGON_DEF_MEM;
        st = tess_derive_master_pass(opt->passphrase, h->salt, h->argon_ops,
                                     h->argon_mem, master);
        if (st != TESS_OK) return st;
    }

    /* sign-then-encrypt: signature lives in the authenticated header */
    if (opt->sign || signature_or_null != NULL) {
        if (opt->sender_secret == NULL || !opt->sender_secret->is_secret ||
            opt->sender_secret->is_locked) {
            tess_master_free(master);
            if (have_eph) sodium_memzero(eph_sk, sizeof eph_sk);
            return TESS_ERR_INVALID_ARG;
        }
        if (signature_or_null != NULL) {
            memcpy(h->signature, signature_or_null, TESS_SIGNATURE_BYTES);
        } else {
            st = tess_sign(pt, pt_len, opt->sender_secret, h->signature);
            if (st != TESS_OK) {
                tess_master_free(master);
                if (have_eph) sodium_memzero(eph_sk, sizeof eph_sk);
                return st;
            }
        }
        memcpy(h->sender_ed_pk, opt->sender_secret->e_pk,
               sizeof h->sender_ed_pk);
        h->flags |= TESS_FLAG_SIGNED;
    }

    st = tess_header_validate(h);
    if (st != TESS_OK) {
        tess_master_free(master);
        if (have_eph) sodium_memzero(eph_sk, sizeof eph_sk);
        return st;
    }
    st = tess_header_serialize(h, hdr_raw);
    if (st != TESS_OK) {
        tess_master_free(master);
        if (have_eph) sodium_memzero(eph_sk, sizeof eph_sk);
        return st;
    }

    /* multi-recipient: wrap the data key under each recipient's DH secret,
     * the block layout is [recipient X25519 pk (32) || sealed key (48)]. */
    if (multi) {
        size_t i;
        if (blocks == NULL) {
            tess_master_free(master);
            if (have_eph) sodium_memzero(eph_sk, sizeof eph_sk);
            return TESS_ERR_INVALID_ARG;
        }
        for (i = 0; i < h->recip_count; i++) {
            tess_master wrap;
            uint8_t aad[TESS_HEADER_BYTES + 32];
            uint8_t *blk = blocks + i * TESS_RECIPIENT_BLOCK_BYTES;
            unsigned long long mlen = 0;

            st = tess_derive_master_pk(eph_sk, opt->recipients[i]->x_pk,
                                       sender_sk, h->salt, &wrap);
            if (st != TESS_OK) break;
            memcpy(blk, opt->recipients[i]->x_pk, 32);
            memcpy(aad, hdr_raw, TESS_HEADER_BYTES);
            memcpy(aad + TESS_HEADER_BYTES, blk, 32);
            if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                    blk + 32, &mlen, master->key, sizeof master->key, aad,
                    sizeof aad, NULL, h->nonce, wrap.key) != 0) {
                tess_master_free(&wrap);
                st = TESS_ERR_INTERNAL;
                break;
            }
            tess_master_free(&wrap);
        }
        if (st != TESS_OK) {
            tess_master_free(master);
            if (have_eph) sodium_memzero(eph_sk, sizeof eph_sk);
            return st;
        }
    }

    if (have_eph) sodium_memzero(eph_sk, sizeof eph_sk);
    return TESS_OK;
}

/* encrypt one chunk; `ct` must have room for pt_len + 16 */
static tess_status seal_chunk(const tess_header *h,
                              const uint8_t hdr_raw[TESS_HEADER_BYTES],
                              const tess_master *master, uint64_t index,
                              int is_final, const uint8_t *pt, size_t pt_len,
                              uint8_t *ct, size_t *ct_len) {
    uint8_t subkey[crypto_kdf_KEYBYTES];
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    uint8_t aad[TESS_HEADER_BYTES + 9];
    unsigned long long mlen = 0;
    tess_status st;

    st = tess_chunk_key(master, index, subkey);
    if (st != TESS_OK) return st;
    tess_chunk_nonce(h->nonce, index, nonce);
    tess_chunk_aad(hdr_raw, index, is_final, aad);

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct, &mlen, pt, (unsigned long long)pt_len, aad, sizeof aad, NULL,
            nonce, subkey) != 0) {
        sodium_memzero(subkey, sizeof subkey);
        return TESS_ERR_INTERNAL;
    }
    sodium_memzero(subkey, sizeof subkey);
    *ct_len = (size_t)mlen;
    return TESS_OK;
}

tess_status tess_seal_buf(const uint8_t *pt, size_t pt_len,
                          const tess_seal_options *opt, uint8_t **out,
                          size_t *out_len) {
    tess_header h;
    uint8_t hdr_raw[TESS_HEADER_BYTES];
    tess_master master;
    uint8_t *buf = NULL;
    uint8_t *blocks = NULL;
    size_t blocks_len = 0;
    size_t total, pos, i, nchunks, cs;
    tess_status st;

    if ((pt == NULL && pt_len > 0) || out == NULL || out_len == NULL) {
        return TESS_ERR_INVALID_ARG;
    }
    *out = NULL;
    *out_len = 0;

    blocks_len = seal_blocks_len(opt);
    if (blocks_len > 0) {
        blocks = (uint8_t *)malloc(blocks_len);
        if (blocks == NULL) return TESS_ERR_NOMEM;
    }

    memset(&master, 0, sizeof master);
    st = seal_prepare(pt, pt_len, NULL, opt, hdr_raw, blocks, &h, &master);
    if (st != TESS_OK) {
        free(blocks);
        return st;
    }

    cs = h.chunk_size;
    nchunks = pt_len == 0 ? 1 : (pt_len + cs - 1) / cs;
    if (nchunks >
        (SIZE_MAX - TESS_HEADER_BYTES - blocks_len) / (cs + 16 + 4)) {
        tess_master_free(&master);
        free(blocks);
        return TESS_ERR_NOMEM;
    }
    total = TESS_HEADER_BYTES + blocks_len + nchunks * (cs + 16 + 4);

    buf = (uint8_t *)malloc(total);
    if (buf == NULL) {
        tess_master_free(&master);
        free(blocks);
        return TESS_ERR_NOMEM;
    }

    memcpy(buf, hdr_raw, TESS_HEADER_BYTES);
    pos = TESS_HEADER_BYTES;
    if (blocks_len > 0) {
        memcpy(buf + pos, blocks, blocks_len);
        pos += blocks_len;
    }
    free(blocks);
    blocks = NULL;

    for (i = 0; i < nchunks; i++) {
        size_t off = i * cs;
        size_t chunk_len = (pt_len - off > cs) ? cs : (pt_len - off);
        int is_final = (i == (size_t)(nchunks - 1));
        size_t ct_len = 0;

        st = seal_chunk(&h, hdr_raw, &master, (uint64_t)i, is_final,
                        pt ? pt + off : NULL, chunk_len, buf + pos + 4,
                        &ct_len);
        if (st != TESS_OK) {
            sodium_memzero(buf, total);
            free(buf);
            tess_master_free(&master);
            return st;
        }
        tess_wr_u32(buf + pos, (uint32_t)ct_len);
        pos += 4 + ct_len;
    }

    tess_master_free(&master);
    *out = buf;
    *out_len = pos;
    return TESS_OK;
}

tess_status tess_seal(const uint8_t *pt, size_t pt_len,
                      const tess_seal_options *opt, uint8_t **out,
                      size_t *out_len) {
    return tess_seal_buf(pt, pt_len, opt, out, out_len);
}

/* ------------------------------------------------------------------ */
/* open — shared machinery                                             */
/* ------------------------------------------------------------------ */

typedef struct open_state {
    tess_header h;
    uint8_t hdr_raw[TESS_HEADER_BYTES];
    tess_master master;
    const tess_open_options *opt;
    size_t body_off; /* first ciphertext byte (after header + key blocks) */
} open_state;

static tess_status open_begin(const uint8_t *hdr_raw, size_t hdr_len,
                              const uint8_t *blocks, size_t blocks_len,
                              const tess_open_options *opt, open_state *st) {
    tess_status rc;

    if (hdr_raw == NULL || opt == NULL) return TESS_ERR_INVALID_ARG;
    if (hdr_len < TESS_HEADER_BYTES) return TESS_ERR_INVALID_ARG;
    memset(st, 0, sizeof *st);
    st->opt = opt;
    memcpy(st->hdr_raw, hdr_raw, TESS_HEADER_BYTES);
    st->body_off = TESS_HEADER_BYTES;

    rc = tess_header_parse(st->hdr_raw, &st->h);
    if (rc != TESS_OK) return rc;

    if (st->h.mode == TESS_MODE_PUBLICKEY) {
        const uint8_t *my_pk = NULL;

        if (opt->recipient_secret == NULL || opt->passphrase != NULL) {
            return TESS_ERR_INVALID_ARG;
        }
        if (!opt->recipient_secret->is_secret) return TESS_ERR_INVALID_ARG;
        if (opt->recipient_secret->is_locked) return TESS_ERR_PASSPHRASE;
        my_pk = opt->recipient_secret->x_pk;

        if (st->h.version == 1) {
            /* message addressed to a single recipient: check it is us */
            if (memcmp(st->h.recipient_pk, my_pk,
                       sizeof st->h.recipient_pk) != 0) {
                return TESS_ERR_RECIPIENT;
            }
            rc = tess_derive_master_open(&st->h, opt->recipient_secret->x_sk,
                                         &st->master);
            if (rc != TESS_OK) return rc;
        } else {
            /* format v2: find our key block and unwrap the data key */
            size_t need = (size_t)st->h.recip_count * TESS_RECIPIENT_BLOCK_BYTES;
            size_t i;
            tess_master wrap;
            int found = 0;

            if (blocks == NULL || blocks_len < need) return TESS_ERR_FORMAT;
            rc = tess_derive_master_open(&st->h, opt->recipient_secret->x_sk,
                                         &wrap);
            if (rc != TESS_OK) return rc;
            for (i = 0; i < st->h.recip_count; i++) {
                const uint8_t *blk = blocks + i * TESS_RECIPIENT_BLOCK_BYTES;
                if (memcmp(blk, my_pk, 32) == 0) {
                    uint8_t aad[TESS_HEADER_BYTES + 32];
                    uint8_t data_key[crypto_kdf_KEYBYTES];
                    unsigned long long mlen = 0;
                    int bad;

                    memcpy(aad, st->hdr_raw, TESS_HEADER_BYTES);
                    memcpy(aad + TESS_HEADER_BYTES, blk, 32);
                    bad = crypto_aead_xchacha20poly1305_ietf_decrypt(
                        data_key, &mlen, NULL, blk + 32,
                        (unsigned long long)(TESS_RECIPIENT_BLOCK_BYTES - 32),
                        aad, sizeof aad, st->h.nonce, wrap.key);
                    if (bad != 0) {
                        sodium_memzero(data_key, sizeof data_key);
                        tess_master_free(&wrap);
                        return TESS_ERR_CRYPTO;
                    }
                    if (mlen != sizeof st->master.key) {
                        sodium_memzero(data_key, sizeof data_key);
                        tess_master_free(&wrap);
                        return TESS_ERR_INTERNAL;
                    }
                    memcpy(st->master.key, data_key, sizeof st->master.key);
                    sodium_memzero(data_key, sizeof data_key);
                    found = 1;
                    break;
                }
            }
            tess_master_free(&wrap);
            if (!found) return TESS_ERR_RECIPIENT;
            st->body_off = TESS_HEADER_BYTES + need;
        }
    } else {
        if (opt->recipient_secret != NULL) return TESS_ERR_INVALID_ARG;
        if (opt->passphrase == NULL || opt->passphrase[0] == '\0') {
            return TESS_ERR_PASSPHRASE;
        }
        rc = tess_derive_master_pass(opt->passphrase, st->h.salt,
                                     st->h.argon_ops, st->h.argon_mem,
                                     &st->master);
        if (rc != TESS_OK) return rc;
    }
    return TESS_OK;
}

/* decrypt one chunk (ct_len includes the 16-byte tag) */
static tess_status open_chunk(const open_state *st, uint64_t index,
                              int is_final, const uint8_t *ct, size_t ct_len,
                              uint8_t *pt, size_t *pt_len) {
    uint8_t subkey[crypto_kdf_KEYBYTES];
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    uint8_t aad[TESS_HEADER_BYTES + 9];
    unsigned long long mlen = 0;
    tess_status rc;

    if (ct_len < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return TESS_ERR_FORMAT;
    }
    rc = tess_chunk_key(&st->master, index, subkey);
    if (rc != TESS_OK) return rc;
    tess_chunk_nonce(st->h.nonce, index, nonce);
    tess_chunk_aad(st->hdr_raw, index, is_final, aad);

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt, &mlen, NULL, ct, (unsigned long long)ct_len, aad, sizeof aad,
            nonce, subkey) != 0) {
        sodium_memzero(subkey, sizeof subkey);
        return TESS_ERR_CRYPTO;
    }
    sodium_memzero(subkey, sizeof subkey);
    *pt_len = (size_t)mlen;
    return TESS_OK;
}

/* signature + signer pinning, checked once all plaintext is available */
static tess_status open_check_signature(const open_state *st,
                                        const uint8_t *pt, size_t pt_len) {
    if ((st->h.flags & TESS_FLAG_SIGNED) == 0) return TESS_OK;

    if (st->opt->required_signer != NULL) {
        if (memcmp(st->opt->required_signer->e_pk, st->h.sender_ed_pk,
                   sizeof st->h.sender_ed_pk) != 0) {
            return TESS_ERR_SIGNER;
        }
    }
    {
        tess_key pub;
        tess_verify_ctx vc;
        tess_status rc;

        memset(&pub, 0, sizeof pub);
        memcpy(pub.e_pk, st->h.sender_ed_pk, sizeof pub.e_pk);
        pub.is_secret = 0;

        tess_verify_begin(&vc);
        rc = tess_verify_update(&vc, pt, pt_len);
        if (rc != TESS_OK) return rc;
        return tess_verify_finish(&vc, &pub, st->h.signature);
    }
}

tess_status tess_open(const uint8_t *ct, size_t ct_len,
                      const tess_open_options *opt, uint8_t **out,
                      size_t *out_len) {
    open_state st;
    tess_status rc;
    uint8_t *buf = NULL;
    size_t cap, pos, outpos = 0, i = 0;

    if (out == NULL || out_len == NULL) return TESS_ERR_INVALID_ARG;
    *out = NULL;
    *out_len = 0;

    rc = open_begin(ct, TESS_HEADER_BYTES, ct + TESS_HEADER_BYTES,
                    ct_len - TESS_HEADER_BYTES, opt, &st);
    if (rc != TESS_OK) return rc;

    cap = (st.h.pt_len != UINT64_MAX) ? (size_t)st.h.pt_len
                                      : (ct_len - st.body_off);
    if (cap < 16) cap = 16;
    buf = (uint8_t *)malloc(cap + 1);
    if (buf == NULL) {
        tess_master_free(&st.master);
        return TESS_ERR_NOMEM;
    }

    pos = st.body_off;
    while (pos < ct_len) {
        uint32_t clen;
        int is_final;
        size_t chunk_pt_len = 0;

        if (ct_len - pos < 4) {
            rc = TESS_ERR_FORMAT;
            goto fail;
        }
        clen = tess_rd_u32(ct + pos);
        pos += 4;
        if (clen < crypto_aead_xchacha20poly1305_ietf_ABYTES ||
            clen > st.h.chunk_size +
                       crypto_aead_xchacha20poly1305_ietf_ABYTES ||
            (size_t)clen > ct_len - pos) {
            rc = TESS_ERR_FORMAT;
            goto fail;
        }
        is_final = (pos + (size_t)clen == ct_len);

        if (outpos + (size_t)clen > cap) {
            size_t ncap = cap * 2 + 64;
            uint8_t *nb;
            while (ncap < outpos + (size_t)clen) ncap *= 2;
            nb = (uint8_t *)realloc(buf, ncap + 1);
            if (nb == NULL) {
                rc = TESS_ERR_NOMEM;
                goto fail;
            }
            buf = nb;
            cap = ncap;
        }
        rc = open_chunk(&st, (uint64_t)i, is_final, ct + pos, clen,
                        buf + outpos, &chunk_pt_len);
        if (rc != TESS_OK) goto fail;
        outpos += chunk_pt_len;
        pos += clen;
        i++;
        if (i > (1ull << 32)) {
            rc = TESS_ERR_FORMAT;
            goto fail;
        }
    }

    if (i == 0) {
        rc = TESS_ERR_FORMAT; /* a valid message always has >= 1 chunk */
        goto fail;
    }
    if (st.h.pt_len != UINT64_MAX && (uint64_t)outpos != st.h.pt_len) {
        rc = TESS_ERR_FORMAT;
        goto fail;
    }

    rc = open_check_signature(&st, buf, outpos);
    if (rc != TESS_OK) goto fail;

    {
        /* output fields live in a caller-owned (nominally const) struct */
        tess_open_options *mut = (tess_open_options *)(uintptr_t)opt;
        if (mut->out_signed != NULL) {
            *mut->out_signed = (st.h.flags & TESS_FLAG_SIGNED) ? 1 : 0;
        }
        memcpy(mut->out_signer_pk, st.h.sender_ed_pk,
               sizeof mut->out_signer_pk);
    }

    tess_master_free(&st.master);
    buf[outpos] = 0;
    *out = buf;
    *out_len = outpos;
    return TESS_OK;

fail:
    sodium_memzero(buf, cap + 1);
    free(buf);
    tess_master_free(&st.master);
    return rc;
}

/* ------------------------------------------------------------------ */
/* file sealing — streaming, atomic output                             */
/* ------------------------------------------------------------------ */

typedef struct part_writer {
    FILE *f;
    char path[4096];
    int failed;
} part_writer;

static tess_status pw_open(part_writer *w, const char *final_path) {
    memset(w, 0, sizeof *w);
    if (snprintf(w->path, sizeof w->path, "%s.part", final_path) >=
        (int)sizeof w->path) {
        return TESS_ERR_INVALID_ARG;
    }
    w->f = fopen(w->path, "wb");
    if (w->f == NULL) return TESS_ERR_IO;
    return TESS_OK;
}

static tess_status pw_write(part_writer *w, const uint8_t *p, size_t n) {
    if (w->failed) return TESS_ERR_IO;
    if (n == 0) return TESS_OK;
    if (fwrite(p, 1, n, w->f) != n) {
        w->failed = 1;
        return TESS_ERR_IO;
    }
    return TESS_OK;
}

static void pw_abort(part_writer *w) {
    if (w->f != NULL) {
        fclose(w->f);
        w->f = NULL;
    }
    if (w->path[0] != '\0') remove(w->path);
}

static tess_status pw_commit(part_writer *w, const char *final_path) {
    if (w->failed) {
        pw_abort(w);
        return TESS_ERR_IO;
    }
    if (fflush(w->f) != 0) {
        pw_abort(w);
        return TESS_ERR_IO;
    }
    fclose(w->f);
    w->f = NULL;
    if (tess_replace_file(w->path, final_path) != 0) {
        remove(w->path);
        return TESS_ERR_IO;
    }
    w->path[0] = '\0';
    return TESS_OK;
}

/* file size via seek; returns TESS_ERR_IO when not seekable */
static tess_status file_size(FILE *f, uint64_t *out) {
    long end;
    *out = 0;
    if (fseek(f, 0, SEEK_END) != 0) return TESS_ERR_IO;
    end = ftell(f);
    if (end < 0) return TESS_ERR_IO;
    if (fseek(f, 0, SEEK_SET) != 0) return TESS_ERR_IO;
    *out = (uint64_t)end;
    return TESS_OK;
}

tess_status tess_seal_file(const char *in_path, const char *out_path,
                           const tess_seal_file_options *opt) {
    FILE *in = NULL;
    tess_header h;
    uint8_t hdr_raw[TESS_HEADER_BYTES];
    tess_master master;
    part_writer pw;
    uint8_t *cur = NULL, *nxt = NULL;
    size_t cs, n_cur = 0, n_nxt = 0;
    uint64_t total_len = 0;
    uint64_t index = 0;
    uint8_t signature[TESS_SIGNATURE_BYTES];
    uint8_t *blocks = NULL;
    size_t blocks_len = 0;
    int have_signature = 0;
    tess_seal_options so;
    tess_status st = TESS_OK;
    int pw_active = 0;

    if (in_path == NULL || out_path == NULL || opt == NULL) {
        return TESS_ERR_INVALID_ARG;
    }
    memset(&master, 0, sizeof master);

    in = fopen(in_path, "rb");
    if (in == NULL) return TESS_ERR_IO;
    st = file_size(in, &total_len);
    if (st != TESS_OK) goto done;

    /* pass 1: signature over the plaintext (streaming) */
    if (opt->sign) {
        if (opt->sender_secret == NULL || !opt->sender_secret->is_secret ||
            opt->sender_secret->is_locked) {
            st = TESS_ERR_INVALID_ARG;
            goto done;
        }
        st = tess_sign_file(in_path, opt->sender_secret, signature);
        if (st != TESS_OK) goto done;
        have_signature = 1;
    }

    tess_seal_options_init(&so);
    so.recipient_public = opt->recipient_public;
    so.recipients = opt->recipients;
    so.recipient_count = opt->recipient_count;
    so.sender_secret = opt->sender_secret;
    so.sign = 0;
    so.passphrase = opt->passphrase;
    so.chunk_size = opt->chunk_size;

    blocks_len = seal_blocks_len(&so);
    if (blocks_len > 0) {
        blocks = (uint8_t *)malloc(blocks_len);
        if (blocks == NULL) {
            st = TESS_ERR_NOMEM;
            goto done;
        }
    }
    st = seal_prepare(NULL, (size_t)total_len, have_signature ? signature : NULL,
                      &so, hdr_raw, blocks, &h, &master);
    if (st != TESS_OK) {
        free(blocks);
        blocks = NULL;
        goto done;
    }

    cs = h.chunk_size;
    cur = (uint8_t *)malloc(cs + 16);
    nxt = (uint8_t *)malloc(cs + 16);
    if (cur == NULL || nxt == NULL) {
        st = TESS_ERR_NOMEM;
        goto done;
    }

    st = pw_open(&pw, out_path);
    if (st != TESS_OK) goto done;
    pw_active = 1;

    st = pw_write(&pw, hdr_raw, TESS_HEADER_BYTES);
    if (st == TESS_OK && blocks_len > 0) st = pw_write(&pw, blocks, blocks_len);
    free(blocks);
    blocks = NULL;
    if (st != TESS_OK) goto done;

    n_cur = fread(cur, 1, cs, in);
    if (ferror(in)) {
        st = TESS_ERR_IO;
        goto done;
    }

    for (;;) {
        size_t ct_cap = cs + 16, ct_len = 0;
        int is_final;
        uint8_t *ctbuf;

        if (n_cur == 0) {
            is_final = 1; /* empty input: single empty final chunk */
        } else {
            n_nxt = fread(nxt, 1, cs, in);
            if (ferror(in)) {
                st = TESS_ERR_IO;
                goto done;
            }
            is_final = (n_nxt == 0);
        }

        ctbuf = (uint8_t *)malloc(ct_cap);
        if (ctbuf == NULL) {
            st = TESS_ERR_NOMEM;
            goto done;
        }
        st = seal_chunk(&h, hdr_raw, &master, index, is_final, cur, n_cur,
                        ctbuf, &ct_len);
        if (st != TESS_OK) {
            free(ctbuf);
            goto done;
        }
        {
            uint8_t lenb[4];
            tess_wr_u32(lenb, (uint32_t)ct_len);
            st = pw_write(&pw, lenb, 4);
            if (st == TESS_OK) st = pw_write(&pw, ctbuf, ct_len);
        }
        free(ctbuf);
        if (st != TESS_OK) goto done;

        index++;
        if (is_final) break;
        {
            uint8_t *tmp = cur;
            cur = nxt;
            nxt = tmp;
            n_cur = n_nxt;
        }
    }

    st = pw_commit(&pw, out_path);
    pw_active = 0;

done:
    if (pw_active) pw_abort(&pw);
    if (in) fclose(in);
    free(cur);
    free(nxt);
    free(blocks);
    tess_master_free(&master);
    return st;
}

/* ------------------------------------------------------------------ */
/* file opening — streaming, atomic output, verify-then-rename         */
/* ------------------------------------------------------------------ */

tess_status tess_open_file(const char *in_path, const char *out_path,
                           const tess_open_file_options *opt) {
    FILE *in = NULL;
    part_writer pw;
    open_state st_ctx;
    uint8_t hdr_raw[TESS_HEADER_BYTES];
    uint64_t total = 0, pos = 0;
    uint64_t index = 0, written = 0;
    uint8_t *ct = NULL;
    uint8_t *blocks = NULL;
    size_t blocks_len = 0;
    tess_verify_ctx vctx;
    int verifying = 0;
    tess_status rc;
    int pw_active = 0;
    tess_open_options oo;
    uint8_t peek[8];

    if (in_path == NULL || out_path == NULL || opt == NULL) {
        return TESS_ERR_INVALID_ARG;
    }
    memset(&st_ctx, 0, sizeof st_ctx);

    in = fopen(in_path, "rb");
    if (in == NULL) return TESS_ERR_IO;

    /* armored input: dearmor into memory and take the buffer path */
    {
        size_t head_len = 0;
        head_len = fread(peek, 1, sizeof peek, in);
        if (fseek(in, 0, SEEK_SET) != 0) {
            fclose(in);
            return TESS_ERR_IO;
        }
        if (head_len >= 5 && peek[0] == '-' && peek[1] == '-' &&
            peek[2] == '-' && peek[3] == '-' && peek[4] == '-') {
            uint8_t *filebuf = NULL;
            size_t filelen = 0;
            uint8_t *raw = NULL;
            size_t rawlen = 0;
            uint8_t *pt = NULL;
            size_t ptlen = 0;

            fclose(in);
            in = NULL;
            rc = tess_read_file(in_path, &filebuf, &filelen);
            if (rc != TESS_OK) goto out;
            rc = tess_dearmor((const char *)filebuf, &raw, &rawlen);
            sodium_memzero(filebuf, filelen);
            free(filebuf);
            if (rc != TESS_OK) goto out;

            tess_open_options_init(&oo);
            oo.recipient_secret = opt->recipient_secret;
            oo.passphrase = opt->passphrase;
            oo.required_signer = opt->required_signer;
            oo.out_signed = opt->out_signed;
            rc = tess_open(raw, rawlen, &oo, &pt, &ptlen);
            sodium_memzero(raw, rawlen);
            free(raw);
            if (rc != TESS_OK) goto out;
            rc = tess_write_file_atomic(out_path, pt, ptlen);
            sodium_memzero(pt, ptlen);
            free(pt);
            goto out;
        }
    }

    memset(&st_ctx, 0, sizeof st_ctx);
    rc = file_size(in, &total);
    if (rc != TESS_OK) goto out;
    if (total < TESS_HEADER_BYTES) {
        rc = TESS_ERR_FORMAT;
        goto out;
    }

    if (fread(hdr_raw, 1, TESS_HEADER_BYTES, in) != TESS_HEADER_BYTES) {
        rc = TESS_ERR_IO;
        goto out;
    }
    pos = TESS_HEADER_BYTES;

    /* format v2: read the recipient key blocks that follow the header */
    {
        tess_header probe;
        rc = tess_header_parse(hdr_raw, &probe);
        if (rc != TESS_OK) goto out;
        if (probe.version == TESS_VERSION_MULTI) {
            blocks_len =
                (size_t)probe.recip_count * TESS_RECIPIENT_BLOCK_BYTES;
            if (total < (uint64_t)pos + blocks_len) {
                rc = TESS_ERR_FORMAT;
                goto out;
            }
            blocks = (uint8_t *)malloc(blocks_len);
            if (blocks == NULL) {
                rc = TESS_ERR_NOMEM;
                goto out;
            }
            if (fread(blocks, 1, blocks_len, in) != blocks_len) {
                rc = TESS_ERR_IO;
                free(blocks);
                blocks = NULL;
                goto out;
            }
            pos += blocks_len;
        }
    }

    tess_open_options_init(&oo);
    oo.recipient_secret = opt->recipient_secret;
    oo.passphrase = opt->passphrase;
    oo.required_signer = opt->required_signer;

    rc = open_begin(hdr_raw, TESS_HEADER_BYTES, blocks, blocks_len, &oo,
                    &st_ctx);
    free(blocks);
    blocks = NULL;
    if (rc != TESS_OK) goto out;

    if ((st_ctx.h.flags & TESS_FLAG_SIGNED) != 0) {
        if (opt->required_signer != NULL &&
            memcmp(opt->required_signer->e_pk, st_ctx.h.sender_ed_pk,
                   sizeof st_ctx.h.sender_ed_pk) != 0) {
            rc = TESS_ERR_SIGNER;
            goto out_state;
        }
        tess_verify_begin(&vctx);
        verifying = 1;
    }

    rc = pw_open(&pw, out_path);
    if (rc != TESS_OK) goto out_state;
    pw_active = 1;

    ct = (uint8_t *)malloc((size_t)st_ctx.h.chunk_size + 16);
    if (ct == NULL) {
        rc = TESS_ERR_NOMEM;
        goto out_state;
    }

    while (pos < total) {
        uint32_t clen;
        int is_final;
        size_t pt_len = 0;
        uint8_t *ptbuf;

        if (total - pos < 4) {
            rc = TESS_ERR_FORMAT;
            goto out_state;
        }
        {
            uint8_t lenb[4];
            if (fread(lenb, 1, 4, in) != 4) {
                rc = TESS_ERR_IO;
                goto out_state;
            }
            clen = tess_rd_u32(lenb);
        }
        pos += 4;
        if (clen < crypto_aead_xchacha20poly1305_ietf_ABYTES ||
            clen > st_ctx.h.chunk_size +
                       crypto_aead_xchacha20poly1305_ietf_ABYTES ||
            (uint64_t)clen > total - pos) {
            rc = TESS_ERR_FORMAT;
            goto out_state;
        }
        if (fread(ct, 1, clen, in) != clen) {
            rc = TESS_ERR_IO;
            goto out_state;
        }
        pos += clen;
        is_final = (pos == total);

        ptbuf = (uint8_t *)malloc((size_t)clen); /* pt <= clen - 16 */
        if (ptbuf == NULL) {
            rc = TESS_ERR_NOMEM;
            goto out_state;
        }
        rc = open_chunk(&st_ctx, index, is_final, ct, clen, ptbuf, &pt_len);
        if (rc != TESS_OK) {
            free(ptbuf);
            goto out_state;
        }
        if (verifying) {
            rc = tess_verify_update(&vctx, ptbuf, pt_len);
            if (rc != TESS_OK) {
                free(ptbuf);
                goto out_state;
            }
        }
        rc = pw_write(&pw, ptbuf, pt_len);
        sodium_memzero(ptbuf, pt_len);
        free(ptbuf);
        if (rc != TESS_OK) goto out_state;
        written += pt_len;
        index++;
    }

    if (st_ctx.h.pt_len != UINT64_MAX &&
        (uint64_t)written != st_ctx.h.pt_len) {
        rc = TESS_ERR_FORMAT;
        goto out_state;
    }

    if (index == 0) {
        rc = TESS_ERR_FORMAT; /* header-only message is never produced */
        goto out_state;
    }

    rc = TESS_OK;

out_state:
    if (verifying && rc == TESS_OK) {
        tess_key pub;
        memset(&pub, 0, sizeof pub);
        memcpy(pub.e_pk, st_ctx.h.sender_ed_pk, sizeof pub.e_pk);
        rc = tess_verify_finish(&vctx, &pub, st_ctx.h.signature);
    }
    if (rc == TESS_OK) {
        rc = pw_commit(&pw, out_path);
        pw_active = 0;
        if (rc == TESS_OK && opt->out_signed != NULL) {
            *opt->out_signed =
                (st_ctx.h.flags & TESS_FLAG_SIGNED) ? 1 : 0;
        }    }
    tess_master_free(&st_ctx.master);

out:
    if (pw_active) pw_abort(&pw);
    if (ct) sodium_memzero(ct, (size_t)st_ctx.h.chunk_size + 16);
    free(ct);
    if (in) fclose(in);
    return rc;
}

/* ------------------------------------------------------------------ */
/* inspection                                                          */
/* ------------------------------------------------------------------ */

tess_status tess_inspect(const uint8_t *data, size_t len,
                         tess_message_info *info) {
    tess_header h;
    tess_status rc;

    if (data == NULL || info == NULL) return TESS_ERR_INVALID_ARG;
    if (len < TESS_HEADER_BYTES) return TESS_ERR_FORMAT;

    rc = tess_header_parse(data, &h);
    if (rc != TESS_OK) return rc;

    memset(info, 0, sizeof *info);
    info->version = h.version;
    info->suite = h.suite;
    info->mode = h.mode;
    info->flags = h.flags;
    info->chunk_size = h.chunk_size;
    info->plaintext_len = h.pt_len;
    info->recipient_count = h.recip_count;
    info->signed_flag = (h.flags & TESS_FLAG_SIGNED) ? 1 : 0;
    memcpy(info->sender_ed25519_pk, h.sender_ed_pk, sizeof h.sender_ed_pk);
    info->has_sender = !all_zero(h.sender_x_pk, sizeof h.sender_x_pk);

    /* fingerprint of the sender identity (x25519 || ed25519) */
    {
        uint8_t in[64];
        uint8_t d[16];
        size_t i;
        static const char hexd[] = "0123456789abcdef";
        memcpy(in, h.sender_x_pk, 32);
        memcpy(in + 32, h.sender_ed_pk, 32);
        if (crypto_generichash(d, sizeof d, in, sizeof in, NULL, 0) == 0) {
            for (i = 0; i < 16; i++) {
                info->fingerprint[i * 2] = hexd[d[i] >> 4];
                info->fingerprint[i * 2 + 1] = hexd[d[i] & 0x0f];
            }
            info->fingerprint[32] = '\0';
        }
        sodium_memzero(in, sizeof in);
        sodium_memzero(d, sizeof d);
    }
    return TESS_OK;
}
