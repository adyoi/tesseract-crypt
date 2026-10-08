/*
 * fuzz_open.c — libFuzzer target for the full tess_open() message entry.
 *
 * Feeds arbitrary bytes through tess_open() with a fixed recipient keypair.
 * Public-key messages (v1 and v2) exercise the header parse, recipient
 * matching, chunk plumbing and error paths, all bounded by TESS_MAX_CHUNK.
 *
 * Passphrase-mode messages are skipped up front: their Argon2id parameters
 * come from attacker-controlled header bytes (the reader's own anti-DoS
 * bounds allow up to 16 rounds and 4 GiB), so passing them to the fuzzer
 * would burn minutes per input for no parser coverage.  Key unlocking is
 * covered by tests/test_keys.c and by libsodium's argon2id internally.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stddef.h>
#include <stdint.h>

#include <sodium.h>

#include <tesseract/tesseract.h>

/* header layout (see src/core/tess_header.c); mode byte is at offset 6 */
#define TESS_OFF_MODE 6u

/* One-time key generation + cleanup for leak-free ASan runs */
static void fuzz_open_cleanup(void)
{
    /* This runs at process exit; libFuzzer calls destructors via __cxa_atexit */
    extern tess_key *fuzz_open_secret, *fuzz_open_public;
    if (fuzz_open_secret) tess_key_free(fuzz_open_secret);
    if (fuzz_open_public) tess_key_free(fuzz_open_public);
}

tess_key *fuzz_open_secret = NULL;
tess_key *fuzz_open_public = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    tess_open_options oo;
    uint8_t *out = NULL;
    size_t out_len = 0;

    if (sodium_init() < 0)
        return 0;
    if (size > (1u << 20))
        return 0; /* messages are small by design */
    if (size < 7)
        return 0; /* no room for the mode byte    */
    if (data[TESS_OFF_MODE] == TESS_MODE_PASSPHRASE)
    {
        return 0; /* skip attacker-controlled KDF DoS cases */
    }

    if (fuzz_open_secret == NULL)
    {
        if (tess_keygen(&fuzz_open_secret, &fuzz_open_public) != TESS_OK)
            return 0;
        /* Register cleanup for ASan leak-free exit */
        atexit(fuzz_open_cleanup);
    }

    tess_open_options_init(&oo);
    oo.recipient_secret = fuzz_open_secret;
    (void)tess_open(data, size, &oo, &out, &out_len);
    if (out != NULL)
        tess_free(out);
    return 0;
}