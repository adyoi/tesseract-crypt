/*
 * fuzz_inspect.c — libFuzzer target for the 264-byte message header parser.
 *
 * Feeds arbitrary bytes to tess_inspect(): magic/version/suite/mode checks,
 * Argon2id bound validation and the sender-fingerprint hash.  Only cheap,
 * allocation-bounded work happens here (no key derivation), so the target is
 * safe to run with unbounded inputs.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stddef.h>
#include <stdint.h>

#include <tesseract/tesseract.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    tess_message_info info;
    (void)tess_inspect(data, size, &info);
    return 0;
}
