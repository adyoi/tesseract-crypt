/*
 * tess_internal.h — shared internals of libtesseract_crypt.
 * Not part of the public API.
 */
#ifndef TESS_INTERNAL_H
#define TESS_INTERNAL_H

#include "tesseract/tesseract.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TESS_MAGIC "TSCR"
#define TESS_MAGIC_LEN 4
#define TESS_VERSION 1
#define TESS_VERSION_MULTI 2
#define TESS_SUITE_1 1

#define TESS_KEY_MAGIC_PRIVATE "TSK1"
#define TESS_KEY_MAGIC_LOCKED "TSK2"
#define TESS_KEY_MAGIC_PUBLIC "TSKp"

#define TESS_KDF_CONTEXT "tesseract-kdf-v1"
#define TESS_CHUNK_CONTEXT "TSCHNK01"
#define TESS_KEY_AAD "tesseract-key-v1"

#define TESS_KEY_BLOB_PRIVATE 164u /* 4 + 32 + 32 + 32 + 64 */
#define TESS_KEY_BLOB_PUBLIC 68u   /* 4 + 32 + 32          */
#define TESS_KEY_BLOB_LOCKED 232u  /* 4+32+32+16+4+8+24+(96+16) */

/* Argon2id hard limits enforced when *reading* untrusted headers/blobs. */
#define TESS_ARGON_MAX_OPS 16u
#define TESS_ARGON_MAX_MEM (4ull * 1024ull * 1024ull * 1024ull)
#define TESS_ARGON_DEF_OPS crypto_pwhash_OPSLIMIT_MODERATE
#define TESS_ARGON_DEF_MEM crypto_pwhash_MEMLIMIT_MODERATE

/* Wire header layout offsets (little-endian, see docs/format.html). */
enum {
    TESS_OFF_MAGIC = 0,
    TESS_OFF_VERSION = 4,
    TESS_OFF_SUITE = 5,
    TESS_OFF_MODE = 6,
    TESS_OFF_FLAGS = 7,
    TESS_OFF_EPH_PK = 8,
    TESS_OFF_RECIPIENT_PK = 40,
    TESS_OFF_RECIPIENT_COUNT = 40, /* format v2 (u32); bytes 44..71 reserved */
    TESS_OFF_SENDER_X_PK = 72,
    TESS_OFF_SENDER_ED_PK = 104,
    TESS_OFF_SIGNATURE = 136,
    TESS_OFF_SALT = 200,
    TESS_OFF_ARGON_OPS = 216,
    TESS_OFF_ARGON_MEM = 220,
    TESS_OFF_NONCE = 228,
    TESS_OFF_CHUNK = 252,
    TESS_OFF_PT_LEN = 256
};

typedef struct tess_header {
    uint8_t version;
    uint8_t suite;
    uint8_t mode;
    uint8_t flags;
    uint8_t eph_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t recipient_pk[crypto_box_PUBLICKEYBYTES];
    uint32_t recip_count;      /* v2: recipient blocks after the header     */
    uint8_t sender_x_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sender_ed_pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t signature[crypto_sign_BYTES];
    uint8_t salt[16];
    uint32_t argon_ops;
    uint64_t argon_mem;
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    uint32_t chunk_size;
    uint64_t pt_len;
} tess_header;

struct tess_key {
    int is_secret;   /* carries private material          */
    int is_locked;   /* private material encrypted        */
    int mem_locked;  /* sodium_mlock() succeeded on alloc */
    uint8_t x_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t x_sk[crypto_box_SECRETKEYBYTES];
    uint8_t e_pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t e_sk[crypto_sign_SECRETKEYBYTES];
    /* locked storage */
    uint8_t lock_salt[16];
    uint32_t lock_ops;
    uint64_t lock_mem;
    uint8_t lock_nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    /* locked secret: x_sk(32) + e_sk(64) + AEAD tag(16) */
    uint8_t lock_blob[96 + crypto_aead_xchacha20poly1305_ietf_ABYTES];
};

/* little-endian helpers (portable, no aliasing issues) */
void tess_wr_u32(uint8_t *p, uint32_t v);
void tess_wr_u64(uint8_t *p, uint64_t v);
uint32_t tess_rd_u32(const uint8_t *p);
uint64_t tess_rd_u64(const uint8_t *p);

/* header */
void tess_header_init(tess_header *h);
tess_status tess_header_serialize(const tess_header *h,
                                  uint8_t out[TESS_HEADER_BYTES]);
tess_status tess_header_parse(const uint8_t in[TESS_HEADER_BYTES],
                              tess_header *h);
tess_status tess_header_validate(const tess_header *h);

/* key schedule */
typedef struct tess_master {
    uint8_t key[crypto_kdf_KEYBYTES];
} tess_master;

void tess_master_free(tess_master *m);

/* mode 1: sender_secret NULL => anonymous (dh_stat = zeros) */
tess_status tess_derive_master_pk(const uint8_t eph_sk[crypto_scalarmult_BYTES],
                                  const uint8_t recipient_pk[crypto_scalarmult_BYTES],
                                  const uint8_t *sender_sk, const uint8_t *salt,
                                  tess_master *out);

tess_status tess_derive_master_open(const tess_header *h,
                                    const uint8_t recipient_sk[crypto_scalarmult_BYTES],
                                    tess_master *out);

tess_status tess_derive_master_pass(const char *passphrase,
                                    const uint8_t salt[16], uint32_t ops,
                                    uint64_t mem, tess_master *out);

/* per-chunk keys */
void tess_chunk_nonce(const uint8_t base[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES],
                      uint64_t index,
                      uint8_t out[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]);
void tess_chunk_aad(const uint8_t header[TESS_HEADER_BYTES], uint64_t index,
                    int is_final, uint8_t out[TESS_HEADER_BYTES + 9]);
tess_status tess_chunk_key(const tess_master *m, uint64_t index,
                           uint8_t out[crypto_kdf_KEYBYTES]);

/* signatures (Ed25519ph streaming) */
typedef struct tess_sign_ctx {
    crypto_sign_state st;
    int active;
} tess_sign_ctx;

void tess_sign_begin(tess_sign_ctx *c);
tess_status tess_sign_update(tess_sign_ctx *c, const uint8_t *m, size_t n);
tess_status tess_sign_finish(tess_sign_ctx *c, const tess_key *secret,
                             uint8_t sig[crypto_sign_BYTES]);

typedef struct tess_verify_ctx {
    crypto_sign_state st;
    int active;
} tess_verify_ctx;

void tess_verify_begin(tess_verify_ctx *c);
tess_status tess_verify_update(tess_verify_ctx *c, const uint8_t *m, size_t n);
tess_status tess_verify_finish(tess_verify_ctx *c, const tess_key *pub,
                               const uint8_t sig[crypto_sign_BYTES]);

/* utilities */
tess_status tess_alloc(size_t n, void **out);
void tess_secure_free(void *p, size_t n);

/* read entire file; *buf allocated with malloc */
tess_status tess_read_file(const char *path, uint8_t **buf, size_t *len);
tess_status tess_write_file_atomic(const char *path, const uint8_t *buf,
                                   size_t len);

/* 64-bit size of an open file (stream repositioned at the start) */
tess_status tess_file_size(FILE *f, uint64_t *out);
/* fflush + fsync/_commit (data at stable storage) */
tess_status tess_sync_file(FILE *f);
/* owner-only mode bits (no-op on Windows, ACLs apply there) */
void tess_restrict_file(FILE *f);

/* replace `to` with `from` (overwrites an existing destination) */
int tess_replace_file(const char *from, const char *to);

int tess_is_locked_blob(const uint8_t *buf, size_t len);

/* seal/open shared helpers */
tess_status tess_seal_buf(const uint8_t *pt, size_t pt_len,
                          const tess_seal_options *opt, uint8_t **out,
                          size_t *out_len);

#endif /* TESS_INTERNAL_H */
