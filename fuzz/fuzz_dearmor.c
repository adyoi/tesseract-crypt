/*
 * fuzz_dearmor.c — libFuzzer target for the PEM-like armor decoder.
 *
 * tess_dearmor() expects a NUL-terminated string (it uses strstr/strchr), so
 * the fuzzer input is copied into a terminated buffer first — exactly how the
 * CLI feeds it.  Decode is pure base64 work: bounded, no crypto.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <tesseract/tesseract.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *text;
    uint8_t *out = NULL;
    size_t out_len = 0;

    if (size > (1u << 20)) return 0; /* 1 MiB cap: armor is small by design */

    text = (char *)malloc(size + 1);
    if (text == NULL) return 0;
    memcpy(text, data, size);
    text[size] = '\0';

    if (tess_dearmor(text, &out, &out_len) == TESS_OK) {
        tess_free(out);
    }
    free(text);
    return 0;
}
