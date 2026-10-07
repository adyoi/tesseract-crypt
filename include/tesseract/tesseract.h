/*
 * tesseract.h — Public C API for libtesseract_crypt.
 *
 * Hybrid public-key encryption (X25519) + passphrase encryption (Argon2id),
 * Ed25519 sign-then-encrypt, chunked streaming AEAD (XChaCha20-Poly1305).
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef TESSERACT_H
#define TESSERACT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TESS_VERSION_MAJOR 0
#define TESS_VERSION_MINOR 1
#define TESS_VERSION_PATCH 0
#define TESS_VERSION_STRING "0.1.0"

/** Fixed sizes of the on-wire format. */
#define TESS_HEADER_BYTES 264u   /* binary message header (magic "TSCR")   */
#define TESS_SIGNATURE_BYTES 64u /* Ed25519 signature                       */
#define TESS_FINGERPRINT_HEX 32u /* BLAKE2b-128 fingerprint, hex encoded    */
#define TESS_DEFAULT_CHUNK (64u * 1024u)
#define TESS_MIN_CHUNK 4096u
#define TESS_MAX_CHUNK (16u * 1024u * 1024u)

/** Multi-recipient messages (format version 2). */
#define TESS_MAX_RECIPIENTS 1024u
#define TESS_RECIPIENT_BLOCK_BYTES 80u /* X25519 pk (32) + wrapped key (48) */

/** Message modes. */
#define TESS_MODE_PUBLICKEY 1
#define TESS_MODE_PASSPHRASE 2

/** Header flag bits. */
#define TESS_FLAG_SIGNED 0x01u

/** Status codes returned by every tess_* function. */
typedef enum tess_status {
    TESS_OK = 0,
    TESS_ERR_INVALID_ARG = 1,
    TESS_ERR_NOMEM = 2,
    TESS_ERR_IO = 3,
    TESS_ERR_FORMAT = 4,     /* bad magic / version / armor / truncated    */
    TESS_ERR_CRYPTO = 5,     /* AEAD authentication failed                 */
    TESS_ERR_PASSPHRASE = 6, /* key is locked or passphrase wrong           */
    TESS_ERR_SIGNATURE = 7,  /* signature verification failed               */
    TESS_ERR_SIGNER = 8,     /* signer not the required one (pinned)        */
    TESS_ERR_UNSUPPORTED = 9,
    TESS_ERR_INTERNAL = 10,
    TESS_ERR_RECIPIENT = 11  /* message is not addressed to this key        */
} tess_status;

/** Opaque key object: a keypair, a private key or a public key. */
typedef struct tess_key tess_key;

/** Read-only view of a parsed message header (see docs/format.html). */
typedef struct tess_message_info {
    int version;              /* format version (1 or 2)                   */
    int suite;                /* algorithm suite (currently 1)             */
    int mode;                 /* TESS_MODE_PUBLICKEY or TESS_MODE_PASSPHRASE */
    unsigned flags;           /* TESS_FLAG_*                               */
    uint32_t chunk_size;      /* plaintext bytes per chunk                 */
    uint64_t plaintext_len;   /* UINT64_MAX if unknown                     */
    uint32_t recipient_count; /* v1: 1, v2: N, passphrase: 0               */
    int has_sender;           /* sender X25519 key present                 */
    int signed_flag;          /* message carries an Ed25519 signature       */
    uint8_t sender_ed25519_pk[32]; /* signer identity (zeros if unsigned)  */
    char fingerprint[TESS_FINGERPRINT_HEX + 1]; /* sender pub fingerprint  */
} tess_message_info;

/* ------------------------------------------------------------------ */
/* Status / version                                                    */
/* ------------------------------------------------------------------ */

const char *tess_strerror(tess_status st);
const char *tess_version(void);

/* ------------------------------------------------------------------ */
/* Keys                                                                */
/* ------------------------------------------------------------------ */

tess_status tess_keygen(tess_key **secret, tess_key **public_key);
tess_status tess_keygen_locked(const char *passphrase, uint32_t ops,
                               uint64_t mem_bytes, tess_key **secret,
                               tess_key **public_key);
tess_status tess_key_unlock(tess_key *key, const char *passphrase);
tess_status tess_key_lock(tess_key *key, const char *passphrase,
                          uint32_t ops, uint64_t mem_bytes);
void tess_key_free(tess_key *key);
tess_status tess_key_get_public(const tess_key *key, tess_key **public_key);
int tess_key_is_secret(const tess_key *key);
int tess_key_is_locked(const tess_key *key);
tess_status tess_key_save(const tess_key *key, const char *path);
tess_status tess_key_load(const char *path, const char *passphrase,
                          tess_key **key);
tess_status tess_key_serialize(const tess_key *key, char **armored);
tess_status tess_key_parse(const char *armored, const char *passphrase,
                           tess_key **key);
tess_status tess_key_fingerprint(const tess_key *key,
                                 char out_hex[TESS_FINGERPRINT_HEX + 1]);

/* ------------------------------------------------------------------ */
/* Seal / open — in-memory buffers                                     */
/* ------------------------------------------------------------------ */

typedef enum tess_key_provider_type {
    TESS_KP_PUB = 0,
    TESS_KP_SEC = 1
} tess_key_provider_type;

typedef tess_status (*tess_key_provider)(const char *id, tess_key_provider_type t,
                                        tess_key **out_key, void *ctx);

typedef struct tess_seal_options {
    const tess_key *recipient_public;
    const char *recipient_public_id;
    const tess_key *const *recipients;
    const char *const *recipient_ids;
    size_t recipient_count;
    const tess_key *sender_secret;
    const char *sender_id;
    int sign;
    const char *passphrase;
    uint32_t chunk_size;
    tess_key_provider key_provider;
    void *key_provider_ctx;
} tess_seal_options;

typedef struct tess_open_options {
    const tess_key *recipient_secret;
    const char *recipient_id;
    const char *passphrase;
    const tess_key *required_signer;
    const char *required_signer_id;
    int *out_signed;
    uint8_t out_signer_pk[32];
    tess_key_provider key_provider;
    void *key_provider_ctx;
} tess_open_options;

void tess_seal_options_init(tess_seal_options *o);
void tess_open_options_init(tess_open_options *o);

tess_status tess_seal(const uint8_t *pt, size_t pt_len,
                       const tess_seal_options *opt, uint8_t **out,
                       size_t *out_len);
tess_status tess_open(const uint8_t *ct, size_t ct_len,
                       const tess_open_options *opt, uint8_t **out,
                       size_t *out_len);
tess_status tess_rekey(const uint8_t *ct, size_t ct_len,
                       const tess_open_options *open_opt,
                       const tess_seal_options *rekey_opt,
                       uint8_t **out, size_t *out_len);
tess_status tess_rekey_buf(const uint8_t *ct, size_t ct_len,
                           const tess_open_options *open_opt,
                           const tess_seal_options *rekey_opt,
                           uint8_t **out, size_t *out_len);

/* ------------------------------------------------------------------ */
/* Seal / open — files (constant memory, atomic output)                */
/* ------------------------------------------------------------------ */

typedef struct tess_seal_file_options {
    const tess_key *recipient_public;
    const char *recipient_public_id;
    const tess_key *const *recipients;
    const char *const *recipient_ids;
    size_t recipient_count;
    const tess_key *sender_secret;
    const char *sender_id;
    int sign;
    const char *passphrase;
    uint32_t chunk_size;
    tess_key_provider key_provider;
    void *key_provider_ctx;
} tess_seal_file_options;

typedef struct tess_open_file_options {
    const tess_key *recipient_secret;
    const char *recipient_id;
    const char *passphrase;
    const tess_key *required_signer;
    const char *required_signer_id;
    int *out_signed;
    tess_key_provider key_provider;
    void *key_provider_ctx;
} tess_open_file_options;

void tess_seal_file_options_init(tess_seal_file_options *o);
void tess_open_file_options_init(tess_open_file_options *o);
tess_status tess_seal_file(const char *in_path, const char *out_path,
                            const tess_seal_file_options *opt);
tess_status tess_open_file(const char *in_path, const char *out_path,
                            const tess_open_file_options *opt);

/* ------------------------------------------------------------------ */
/* Detached signatures (Ed25519ph, streaming)                          */
/* ------------------------------------------------------------------ */

tess_status tess_sign(const uint8_t *msg, size_t msg_len, const tess_key *secret,
                       uint8_t sig[TESS_SIGNATURE_BYTES]);
tess_status tess_verify(const uint8_t *msg, size_t msg_len,
                         const tess_key *public_key,
                         const uint8_t sig[TESS_SIGNATURE_BYTES]);
tess_status tess_sign_file(const char *path, const tess_key *secret,
                            uint8_t sig[TESS_SIGNATURE_BYTES]);
tess_status tess_verify_file(const char *path, const tess_key *public_key,
                              const uint8_t sig[TESS_SIGNATURE_BYTES]);

/* ------------------------------------------------------------------ */
/* Armor (PEM-like base64 wrapper)                                     */
/* ------------------------------------------------------------------ */

tess_status tess_armor(const uint8_t *in, size_t len, const char *label,
                        char **out);
tess_status tess_dearmor(const char *text, uint8_t **out, size_t *out_len);
int tess_is_armored(const uint8_t *data, size_t len);

/* ------------------------------------------------------------------ */
/* Inspection                                                          */
/* ------------------------------------------------------------------ */

tess_status tess_inspect(const uint8_t *data, size_t len,
                          tess_message_info *info);

/* ------------------------------------------------------------------ */
/* Memory                                                              */
/* ------------------------------------------------------------------ */

void tess_free(void *ptr);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TESSERACT_H */
