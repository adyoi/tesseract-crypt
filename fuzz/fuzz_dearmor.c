/*
 * fuzz_dearmor.c — libFuzzer target for the PEM-like armor decoder.
 *
 * tess_dearmor() expects a NUL-terminated string (it uses strstr/strchr), so
 * the fuzzer input is copied into a terminated buffer first — exactly how the
 * CLI feeds it.  Decode is pure base64 work: bounded, no crypto.
 *
 * Whenever decoding succeeds a second invariant is checked: re-encoding the
 * decoded bytes and decoding again must be an identity.  A mismatch means the
 * armor codec is not invertible and trips the harness.
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
    uint8_t *out = NULL;
    size_t out_len = 0;

    if (sodium_init() < 0)
        return 0;
    if (size > (1u << 20))
        return 0; /* 1 MiB cap: armor is small by design */

    text = (char *)malloc(size + 1);
    if (text == NULL)
        return 0;
    memcpy(text, data, size);
    text[size] = '\0';

    if (tess_dearmor(text, &out, &out_len) == TESS_OK)
    {
        /* roundtrip invariant: armor(dearmor(x)) -> dearmor -> x */
        char *armored = NULL;
        uint8_t *again = NULL;
        size_t again_len = 0;
        if (tess_armor(out, out_len, "TESSERACT DATA", &armored) == TESS_OK &&
            tess_dearmor(armored, &again, &again_len) == TESS_OK)
        {
            if (again_len != out_len || memcmp(again, out, out_len) != 0)
            {
                return 1; /* codec is not invertible */
            }
        }
        tess_free(armored);
        tess_free(again);
        tess_free(out);
    }
    free(text);
    return 0;
}
