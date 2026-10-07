/* tess_keys.c — key generation, locking (Argon2id), file/armor I/O. */
#include "tess_internal.h"

#include <sodium.h>
#include <sodium/utils.h>

/* ------------------------------------------------------------------ */
/* basics                                                              */
/* ------------------------------------------------------------------ */

void tess_key_free(tess_key *key) {
    if (key == NULL) return;
    sodium_memzero(key, sizeof *key);
    if (key->mem_locked) sodium_munlock(key, sizeof *key);
    free(key);
}

int tess_key_is_secret(const tess_key *key) {
    return key != NULL && key->is_secret;
}

int tess_key_is_locked(const tess_key *key) {
    return key != NULL && key->is_locked;
}

static tess_status key_alloc(tess_key **out) {
    tess_key *k;
    if (out == NULL) return TESS_ERR_INVALID_ARG;
    *out = NULL;
    k = (tess_key *)calloc(1, sizeof *k);
    if (k == NULL) return TESS_ERR_NOMEM;
    /* best effort: keep the key material out of the swap area */
    k->mem_locked = sodium_mlock(k, sizeof *k) == 0;
    *out = k;
    return TESS_OK;
}

tess_status tess_keygen(tess_key **secret, tess_key **public_key) {
    tess_key *s = NULL;
    tess_status st;

    if (secret == NULL || public_key == NULL) return TESS_ERR_INVALID_ARG;
    *secret = NULL;
    *public_key = NULL;

    st = key_alloc(&s);
    if (st != TESS_OK) return st;

    randombytes_buf(s->x_sk, sizeof s->x_sk);
    if (crypto_scalarmult_base(s->x_pk, s->x_sk) != 0) {
        tess_key_free(s);
        return TESS_ERR_INTERNAL;
    }
    crypto_sign_keypair(s->e_pk, s->e_sk);
    s->is_secret = 1;
    s->is_locked = 0;

    *secret = s;
    return tess_key_get_public(s, public_key);
}

tess_status tess_key_get_public(const tess_key *key, tess_key **public_key) {
    tess_key *p;
    tess_status st;

    if (key == NULL || public_key == NULL) return TESS_ERR_INVALID_ARG;
    *public_key = NULL;
    st = key_alloc(&p);
    if (st != TESS_OK) return st;
    memcpy(p->x_pk, key->x_pk, sizeof p->x_pk);
    memcpy(p->e_pk, key->e_pk, sizeof p->e_pk);
    p->is_secret = 0;
    p->is_locked = 0;
    *public_key = p;
    return TESS_OK;
}

/* ------------------------------------------------------------------ */
/* locking with Argon2id                                               */
/* ------------------------------------------------------------------ */

static tess_status argon_params(uint32_t ops_in, uint64_t mem_in,
                                uint32_t *ops, uint64_t *mem) {
    *ops = ops_in ? ops_in : (uint32_t)TESS_ARGON_DEF_OPS;
    *mem = mem_in ? mem_in : (uint64_t)TESS_ARGON_DEF_MEM;
    if (*ops < 1 || *ops > TESS_ARGON_MAX_OPS) return TESS_ERR_INVALID_ARG;
    if (*mem < (64ull * 1024ull) || *mem > TESS_ARGON_MAX_MEM) {
        return TESS_ERR_INVALID_ARG;
    }
    return TESS_OK;
}

/* pack the 160-byte private blob into buf (TSK1) */
static void pack_private(const tess_key *k, uint8_t blob[160]) {
    memcpy(blob, k->x_pk, 32);
    memcpy(blob + 32, k->x_sk, 32);
    memcpy(blob + 64, k->e_pk, 32);
    memcpy(blob + 96, k->e_sk, 64);
}

static void unpack_private(tess_key *k, const uint8_t blob[160]) {
    memcpy(k->x_pk, blob, 32);
    memcpy(k->x_sk, blob + 32, 32);
    memcpy(k->e_pk, blob + 64, 32);
    memcpy(k->e_sk, blob + 96, 64);
}

/* the locked part: only secret scalars (96 bytes); public keys stay clear */
static void pack_secret(const tess_key *k, uint8_t blob[96]) {
    memcpy(blob, k->x_sk, 32);
    memcpy(blob + 32, k->e_sk, 64);
}

static tess_status lock_derive(const char *pass, const uint8_t salt[16],
                               uint32_t ops, uint64_t mem,
                               uint8_t key[crypto_kdf_KEYBYTES]) {
    /* parameters are validated by the callers; a failure here is an
     * allocation failure inside Argon2id */
    if (crypto_pwhash(key, crypto_kdf_KEYBYTES, pass, strlen(pass), salt,
                      ops, mem, crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return TESS_ERR_NOMEM;
    }
    return TESS_OK;
}

static tess_status key_lock_into(tess_key *k, const char *passphrase,
                                 uint32_t ops, uint64_t mem) {
    uint8_t blob[96];
    uint8_t subkey[crypto_kdf_KEYBYTES];
    unsigned long long clen = 0;
    tess_status st;

    if (passphrase == NULL || passphrase[0] == '\0') {
        return TESS_ERR_INVALID_ARG;
    }
    /* already locked: the secret scalars are gone, re-locking would pack
     * zeros and destroy the key — unlock first. */
    if (k->is_locked) return TESS_ERR_INVALID_ARG;
    st = argon_params(ops, mem, &ops, &mem);
    if (st != TESS_OK) return st;

    randombytes_buf(k->lock_salt, sizeof k->lock_salt);
    randombytes_buf(k->lock_nonce, sizeof k->lock_nonce);
    st = lock_derive(passphrase, k->lock_salt, ops, mem, subkey);
    if (st != TESS_OK) {
        sodium_memzero(subkey, sizeof subkey);
        return st;
    }
    k->lock_ops = ops;
    k->lock_mem = mem;

    pack_secret(k, blob);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            k->lock_blob, &clen, blob, sizeof blob,
            (const unsigned char *)TESS_KEY_AAD,
            (unsigned long long)strlen(TESS_KEY_AAD), NULL, k->lock_nonce,
            subkey) != 0) {
        sodium_memzero(blob, sizeof blob);
        sodium_memzero(subkey, sizeof subkey);
        return TESS_ERR_INTERNAL;
    }
    sodium_memzero(blob, sizeof blob);
    sodium_memzero(subkey, sizeof subkey);
    /* the plaintext scalars now live only in lock_blob */
    sodium_memzero(k->x_sk, sizeof k->x_sk);
    sodium_memzero(k->e_sk, sizeof k->e_sk);
    k->is_locked = 1;
    return TESS_OK;
}

tess_status tess_key_lock(tess_key *key, const char *passphrase,
                          uint32_t ops, uint64_t mem) {
    if (key == NULL || !key->is_secret) return TESS_ERR_INVALID_ARG;
    return key_lock_into(key, passphrase, ops, mem);
}

tess_status tess_key_unlock(tess_key *key, const char *passphrase) {
    uint8_t subkey[crypto_kdf_KEYBYTES];
    uint8_t blob[96];
    unsigned long long blen = 0;
    tess_status st;

    if (key == NULL || !key->is_secret) return TESS_ERR_INVALID_ARG;
    if (!key->is_locked) return TESS_OK;
    if (passphrase == NULL || passphrase[0] == '\0') {
        return TESS_ERR_PASSPHRASE;
    }
    if (key->lock_ops < 1 || key->lock_ops > TESS_ARGON_MAX_OPS ||
        key->lock_mem < (64ull * 1024ull) ||
        key->lock_mem > TESS_ARGON_MAX_MEM) {
        return TESS_ERR_FORMAT;
    }

    st = lock_derive(passphrase, key->lock_salt, key->lock_ops, key->lock_mem,
                     subkey);
    if (st != TESS_OK) {
        sodium_memzero(subkey, sizeof subkey);
        return st;
    }
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            blob, &blen, NULL, key->lock_blob,
            (unsigned long long)sizeof key->lock_blob,
            (const unsigned char *)TESS_KEY_AAD,
            (unsigned long long)strlen(TESS_KEY_AAD), key->lock_nonce,
            subkey) != 0) {
        sodium_memzero(subkey, sizeof subkey);
        sodium_memzero(blob, sizeof blob);
        return TESS_ERR_PASSPHRASE;
    }
    sodium_memzero(subkey, sizeof subkey);
    if (blen != sizeof blob) {
        sodium_memzero(blob, sizeof blob);
        return TESS_ERR_INTERNAL;
    }
    memcpy(key->x_sk, blob, 32);
    memcpy(key->e_sk, blob + 32, 64);
    sodium_memzero(blob, sizeof blob);
    key->is_locked = 0;
    return TESS_OK;
}

tess_status tess_keygen_locked(const char *passphrase, uint32_t ops,
                               uint64_t mem_bytes, tess_key **secret,
                               tess_key **public_key) {
    tess_status st = tess_keygen(secret, public_key);
    if (st != TESS_OK) return st;
    st = key_lock_into(*secret, passphrase, ops, mem_bytes);
    if (st != TESS_OK) {
        tess_key_free(*secret);
        tess_key_free(*public_key);
        *secret = NULL;
        *public_key = NULL;
    }
    return st;
}

/* ------------------------------------------------------------------ */
/* serialization                                                       */
/* ------------------------------------------------------------------ */

static const char *label_for(const tess_key *k) {
    if (!k->is_secret) return "TESSERACT PUBLIC KEY";
    return k->is_locked ? "TESSERACT PRIVATE KEY (LOCKED)"
                        : "TESSERACT PRIVATE KEY";
}

tess_status tess_key_serialize(const tess_key *key, char **armored) {
    uint8_t buf[256];
    size_t n = 0;
    tess_status st;

    if (key == NULL || armored == NULL) return TESS_ERR_INVALID_ARG;
    *armored = NULL;

    if (!key->is_secret) {
        memcpy(buf, TESS_KEY_MAGIC_PUBLIC, 4);
        memcpy(buf + 4, key->x_pk, 32);
        memcpy(buf + 36, key->e_pk, 32);
        n = TESS_KEY_BLOB_PUBLIC;
    } else if (key->is_locked) {
        memcpy(buf, TESS_KEY_MAGIC_LOCKED, 4);
        memcpy(buf + 4, key->x_pk, 32);   /* public half stays clear   */
        memcpy(buf + 36, key->e_pk, 32);
        memcpy(buf + 68, key->lock_salt, 16);
        tess_wr_u32(buf + 84, key->lock_ops);
        tess_wr_u64(buf + 88, key->lock_mem);
        memcpy(buf + 96, key->lock_nonce, 24);
        memcpy(buf + 120, key->lock_blob, sizeof key->lock_blob);
        n = 120 + sizeof key->lock_blob; /* 232 */
    } else {
        memcpy(buf, TESS_KEY_MAGIC_PRIVATE, 4);
        pack_private(key, buf + 4);
        n = TESS_KEY_BLOB_PRIVATE; /* 164 */
    }
    st = tess_armor(buf, n, label_for(key), armored);
    sodium_memzero(buf, sizeof buf); /* may hold private material */
    return st;
}

tess_status tess_key_parse(const char *armored, const char *passphrase,
                           tess_key **key) {
    uint8_t *raw = NULL;
    size_t len = 0;
    tess_status st;
    tess_key *k = NULL;

    if (armored == NULL || key == NULL) return TESS_ERR_INVALID_ARG;
    *key = NULL;

    st = tess_dearmor(armored, &raw, &len);
    if (st != TESS_OK) return st;

    if (len < 4) {
        free(raw);
        return TESS_ERR_FORMAT;
    }

    st = key_alloc(&k);
    if (st != TESS_OK) {
        free(raw);
        return st;
    }

    if (memcmp(raw, TESS_KEY_MAGIC_PUBLIC, 4) == 0) {
        if (len != TESS_KEY_BLOB_PUBLIC) {
            st = TESS_ERR_FORMAT;
            goto fail;
        }
        memcpy(k->x_pk, raw + 4, 32);
        memcpy(k->e_pk, raw + 36, 32);
        k->is_secret = 0;
        k->is_locked = 0;
    } else if (memcmp(raw, TESS_KEY_MAGIC_PRIVATE, 4) == 0) {
        if (len != TESS_KEY_BLOB_PRIVATE) {
            st = TESS_ERR_FORMAT;
            goto fail;
        }
        unpack_private(k, raw + 4);
        k->is_secret = 1;
        k->is_locked = 0;
    } else if (memcmp(raw, TESS_KEY_MAGIC_LOCKED, 4) == 0) {
        if (len != TESS_KEY_BLOB_LOCKED) {
            st = TESS_ERR_FORMAT;
            goto fail;
        }
        k->is_secret = 1;
        /* public half is stored in the clear: fingerprint works locked */
        memcpy(k->x_pk, raw + 4, 32);
        memcpy(k->e_pk, raw + 36, 32);
        memcpy(k->lock_salt, raw + 68, 16);
        k->lock_ops = tess_rd_u32(raw + 84);
        k->lock_mem = tess_rd_u64(raw + 88);
        memcpy(k->lock_nonce, raw + 96, 24);
        memcpy(k->lock_blob, raw + 120, sizeof k->lock_blob);
        k->is_locked = 1;
        if (passphrase == NULL || passphrase[0] == '\0') {
            st = TESS_ERR_PASSPHRASE;
            goto fail;
        }
        st = tess_key_unlock(k, passphrase);
        if (st != TESS_OK) goto fail;
    } else {
        st = TESS_ERR_FORMAT;
        goto fail;
    }

    sodium_memzero(raw, len);
    free(raw);
    *key = k;
    return TESS_OK;

fail:
    sodium_memzero(raw, len);
    free(raw);
    tess_key_free(k);
    return st;
}

/* ------------------------------------------------------------------ */
/* file I/O                                                            */
/* ------------------------------------------------------------------ */

tess_status tess_key_save(const tess_key *key, const char *path) {
    char *armored = NULL;
    tess_status st;

    if (key == NULL || path == NULL) return TESS_ERR_INVALID_ARG;
    st = tess_key_serialize(key, &armored);
    if (st != TESS_OK) return st;
    st = tess_write_file_atomic(path, (const uint8_t *)armored,
                                strlen(armored));
    sodium_memzero(armored, strlen(armored)); /* private material */
    free(armored);
    return st;
}

tess_status tess_key_load(const char *path, const char *passphrase,
                          tess_key **key) {
    uint8_t *buf = NULL;
    size_t len = 0;
    tess_status st;

    if (path == NULL || key == NULL) return TESS_ERR_INVALID_ARG;
    *key = NULL;
    st = tess_read_file(path, &buf, &len);
    if (st != TESS_OK) return st;
    st = tess_key_parse((const char *)buf, passphrase, key);
    sodium_memzero(buf, len);
    free(buf);
    return st;
}

/* ------------------------------------------------------------------ */
/* fingerprint                                                         */
/* ------------------------------------------------------------------ */

tess_status tess_key_fingerprint(const tess_key *key,
                                 char out_hex[TESS_FINGERPRINT_HEX + 1]) {
    uint8_t digest[16];
    uint8_t in[64];
    char hex[TESS_FINGERPRINT_HEX + 1];
    size_t i;

    if (key == NULL || out_hex == NULL) return TESS_ERR_INVALID_ARG;

    memcpy(in, key->x_pk, 32);
    memcpy(in + 32, key->e_pk, 32);
    if (crypto_generichash(digest, sizeof digest, in, sizeof in, NULL, 0) != 0) {
        return TESS_ERR_INTERNAL;
    }
    for (i = 0; i < 16; i++) {
        static const char d[] = "0123456789abcdef";
        hex[i * 2] = d[digest[i] >> 4];
        hex[i * 2 + 1] = d[digest[i] & 0x0f];
    }
    hex[32] = '\0';
    sodium_memzero(digest, sizeof digest);
    sodium_memzero(in, sizeof in);
    memcpy(out_hex, hex, sizeof hex);
    return TESS_OK;
}
