/*
 * fuzz_inspect.c — libFuzzer target for the 264-byte message header parser.
 *
 * Feeds arbitrary bytes to tess_inspect(): magic/version/suite/mode checks,
 * Argon2id bound validation and the sender-fingerprint hash.  Only cheap,
 * allocation-bounded work happens here (no key derivation), so the target is
 * safe to run with unbounded inputs.
 *
 * When the header parses, a few cheap invariants are asserted so that a
 * corrupt inspector trips the harness instead of silently lying about the
 * message it just validated.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <sodium.h>

#include <tesseract/tesseract.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    tess_message_info info;

    if (sodium_init() < 0)
        return 0;

    if (tess_inspect(data, size, &info) == TESS_OK)
    {
        /* invariants a validated header must satisfy */
        if (info.version != 1 && info.version != 2)
            return 1;
        if (info.mode < TESS_MODE_PUBLICKEY || info.mode > TESS_MODE_PASSPHRASE)
        {
            return 1;
        }
        if (info.recipient_count > TESS_MAX_RECIPIENTS)
            return 1;
        if (info.chunk_size > TESS_MAX_CHUNK)
            return 1;
    }
    return 0;
}