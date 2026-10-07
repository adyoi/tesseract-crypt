/*
 * fuzz_key_parse.c — libFuzzer target for the armored key parser (TSK1 /
 * TSK2 / TSKp).
 *
 * The passphrase is intentionally NULL: for locked (TSK2) keys tess_key_parse
 * returns TESS_ERR_PASSPHRASE *before* any Argon2id work, so the structural
 * parser — magic checks, blob lengths, public-half extraction — is fuzzed
 * while attacker-controlled lock_ops/lock_mem can never trigger a 4 GiB /
 * 16-round KDF inside the fuzzer.  Unlocking is covered by tests/test_keys.c.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include <tesseract/tesseract.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *text;
    tess_key *key = NULL;

    if (sodium_init() < 0)
        return 0;
    if (size > (1u << 20))
        return 0; /* key blobs are <= 1 KiB armored */

    text = (char *)malloc(size + 1);
    if (text == NULL)
        return 0;
    memcpy(text, data, size);
    text[size] = '\0';

    if (tess_key_parse(text, NULL, &key) == TESS_OK)
    {
        tess_key_free(key);
    }
    free(text);
    return 0;
}
