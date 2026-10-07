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
    TESS_ERR_INTERNAL = 10
} tess_status;

/** Opaque key object: a keypair, a private key or a public key. */
typedef struct tess_key tess_key;

/** Read-only view of a parsed message header (see docs/format.html). */
typedef struct tess_message_info {
    int version;              /* format version (currently 1)              */
    int suite;                /* algorithm suite (currently 1)             */
    int mode;                 /* TESS_MODE_PUBLICKEY or TESS_MODE_PASSPHRASE */
    unsigned flags;           /* TESS_FLAG_*                               */
    uint32_t chunk_size;      /* plaintext bytes per chunk                 */
    uint64_t plaintext_len;   /* UINT64_MAX if unknown                     */
    int has_sender;           /* sender X25519 key present                 */
    int signed_flag;          /* message carries an Ed25519 signature       */
    uint8_t sender_ed25519_pk[32]; /* signer identity (zeros if unsigned)  */
    char fingerprint[TESS_FINGERPRINT_HEX + 1]; /* sender pub fingerprint  */
} tess_message_info;

/* ------------------------------------------------------------------ */
/* Status / version                                                    */
/* ------------------------------------------------------------------ */

/** Human readable message for a status code (never NULL). */
const char *tess_strerror(tess_status st);

/** Library version string, e.g. "0.1.0". */
const char *tess_version(void);

/* ------------------------------------------------------------------ */
/* Keys                                                                */
/* ------------------------------------------------------------------ */

/**
 * Generate a fresh keypair (X25519 for encryption + Ed25519 for signing).
 * On success *secret and *public_key are set; free both with tess_key_free().
 */
tess_status tess_keygen(tess_key **secret, tess_key **public_key);

/**
 * Generate a keypair whose secret material is immediately locked with
 * Argon2id(passphrase, ...).  The resulting secret key can only be saved
 * (tess_key_save) or used after tess_key_unlock() succeeds.
 * ops = 0 / mem = 0 select the library defaults (moderate).
 */
tess_status tess_keygen_locked(const char *passphrase, uint32_t ops,
                               uint64_t mem_bytes, tess_key **secret,
                               tess_key **public_key);

/** Unlock a locked private key in memory (no-op if already unlocked). */
tess_status tess_key_unlock(tess_key *key, const char *passphrase);

/** Lock an unlocked private key in memory with a passphrase. */
tess_status tess_key_lock(tess_key *key, const char *passphrase,
                          uint32_t ops, uint64_t mem_bytes);

/** Zero and free a key object (NULL tolerated). */
void tess_key_free(tess_key *key);

/** Extract the public part of a key (works for secret and public keys). */
tess_status tess_key_get_public(const tess_key *key, tess_key **public_key);

/** 1 if this key carries private material, 0 otherwise. */
int tess_key_is_secret(const tess_key *key);

/** 1 if this key's private material is locked with a passphrase. */
int tess_key_is_locked(const tess_key *key);

/** Save key as an armored key file (private or public depending on key). */
tess_status tess_key_save(const tess_key *key, const char *path);

/** Load a key file.  passphrase may be NULL for unlocked keys. */
tess_status tess_key_load(const char *path, const char *passphrase,
                          tess_key **key);

/** Encode key into an allocated armored string (caller frees with tess_free). */
tess_status tess_key_serialize(const tess_key *key, char **armored);

/** Parse an armored key string (passphrase may be NULL). */
tess_status tess_key_parse(const char *armored, const char *passphrase,
                           tess_key **key);

/**
 * BLAKE2b-128 fingerprint of the public key as lowercase hex
 * (TESS_FINGERPRINT_HEX chars + NUL).  Works on secret keys too.
 */
tess_status tess_key_fingerprint(const tess_key *key,
                                 char out_hex[TESS_FINGERPRINT_HEX + 1]);

/* ------------------------------------------------------------------ */
/* Seal / open — in-memory buffers                                     */
/* ------------------------------------------------------------------ */

typedef struct tess_seal_options {
    const tess_key *recipient_public; /* NULL => passphrase mode          */
    const tess_key *sender_secret;    /* NULL => anonymous, unsigned      */
    int sign;                         /* sign plaintext? (needs sender)   */
    const char *passphrase;           /* used iff recipient_public == NULL */
    uint32_t chunk_size;              /* 0 => TESS_DEFAULT_CHUNK          */
} tess_seal_options;

typedef struct tess_open_options {
    const tess_key *recipient_secret; /* NULL => passphrase mode          */
    const char *passphrase;           /* used iff recipient_secret == NULL */
    const tess_key *required_signer;  /* NULL => accept any signer         */
    int *out_signed;                  /* optional: 1 if msg was signed     */
    uint8_t out_signer_pk[32];        /* optional: signer Ed25519 pk       */
} tess_open_options;

/** Fill options with defaults (all NULL/0). */
void tess_seal_options_init(tess_seal_options *o);
void tess_open_options_init(tess_open_options *o);

/**
 * Encrypt pt[0..pt_len] into a freshly allocated ciphertext buffer
 * (*out is allocated with malloc; release with tess_free()).
 */
tess_status tess_seal(const uint8_t *pt, size_t pt_len,
                      const tess_seal_options *opt, uint8_t **out,
                      size_t *out_len);

/**
 * Decrypt a ciphertext produced by tess_seal().  On success *out holds the
 * plaintext (release with tess_free()).
 */
tess_status tess_open(const uint8_t *ct, size_t ct_len,
                      const tess_open_options *opt, uint8_t **out,
                      size_t *out_len);

/* ------------------------------------------------------------------ */
/* Seal / open — files (constant memory, atomic output)                */
/* ------------------------------------------------------------------ */

typedef struct tess_seal_file_options {
    const tess_key *recipient_public;
    const tess_key *sender_secret;
    int sign;
    const char *passphrase;
    uint32_t chunk_size;
} tess_seal_file_options;

typedef struct tess_open_file_options {
    const tess_key *recipient_secret;
    const char *passphrase;
    const tess_key *required_signer;
    int *out_signed; /* optional: set to 1 when the message was signed */
} tess_open_file_options;

void tess_seal_file_options_init(tess_seal_file_options *o);
void tess_open_file_options_init(tess_open_file_options *o);

/**
 * Encrypt file `in_path` into `out_path`.  Output is written to
 * `out_path + ".part"` and atomically renamed on success.
 */
tess_status tess_seal_file(const char *in_path, const char *out_path,
                           const tess_seal_file_options *opt);

/**
 * Decrypt file `in_path` into `out_path`.  The plaintext is written to a
 * `.part` file and only renamed to `out_path` after the signature (if any)
 * has verified — unauthenticated data never appears at the final path.
 */
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

/** Allocate an armored encoding of in[0..len] with the given label. */
tess_status tess_armor(const uint8_t *in, size_t len, const char *label,
                       char **out);

/** Decode an armored block back to binary (label is not checked strictly). */
tess_status tess_dearmor(const char *text, uint8_t **out, size_t *out_len);

/** 1 if the buffer looks like an armored Tesseract message. */
int tess_is_armored(const uint8_t *data, size_t len);

/* ------------------------------------------------------------------ */
/* Inspection                                                          */
/* ------------------------------------------------------------------ */

/** Parse (and validate) the 264-byte header at the start of a message. */
tess_status tess_inspect(const uint8_t *data, size_t len,
                         tess_message_info *info);

/** Free memory returned by the library (tess_seal, tess_armor, ...). */
void tess_free(void *ptr);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TESSERACT_H */
