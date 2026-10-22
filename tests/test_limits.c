/*
 * test_limits.c — the decryptor must not let the message it reads decide how
 * much memory it allocates.
 *
 * A message header carries the plaintext length, and that field is under the
 * control of whoever produced the message.  The old code trusted it for the
 * initial buffer of tess_open(), so a 300-byte hostile message announcing
 * "4 GiB" made the decryptor malloc that much before it read a single
 * ciphertext byte (memory-exhaustion DoS).  The plaintext of a message can
 * never be larger than the ciphertext that carries it, so the buffer is now
 * clamped to what the ciphertext could possibly hold.
 *
 * This test runs the two cases back to back in one process and compares the
 * working set of the process, which is what a DoS actually consumes.
 */
#include "common.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
static size_t working_set_kb(void) {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof pmc)) {
        return (size_t)(pmc.WorkingSetSize / 1024);
    }
    return 0;
}
#else
#include <stdio.h>
#include <unistd.h>
/* /proc/self/statm reports resident pages: good enough to spot a gigabyte. */
static size_t working_set_kb(void) {
    FILE *f = fopen("/proc/self/statm", "r");
    unsigned long total = 0, resident = 0;
    long page = sysconf(_SC_PAGESIZE);
    if (!f) return 0;
    if (fscanf(f, "%lu %lu", &total, &resident) != 2) resident = 0;
    fclose(f);
    return (size_t)(resident * (size_t)page / 1024);
}
#endif

#define TESS_OFF_PT_LEN_TEST 256u /* see src/core/tess_internal.h */

/* A hostile header may not buy the attacker more than the message is long. */
#define MAX_GROWTH_KB (64u * 1024u) /* 64 MiB: far below the 4 GiB announced */

int main(void) {
    tess_key *bob_sec = NULL, *bob_pub = NULL;
    uint8_t *pt = NULL;
    size_t pt_len = 20000;
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    tess_seal_options so;
    tess_open_options oo;
    uint8_t *out = NULL;
    size_t out_len = 0;
    size_t before, after;

    CHECK(sodium_init() >= 0);
    CHECK_ST(tess_keygen(&bob_sec, &bob_pub), TESS_OK);
    pt = fill_pattern(pt_len, 11);

    tess_seal_options_init(&so);
    so.recipient_public = bob_pub;
    so.chunk_size = 4096;
    CHECK_ST(tess_seal(pt, pt_len, &so, &ct, &ct_len), TESS_OK);
    CHECK(ct_len > TESS_HEADER_BYTES);

    /* the header really does carry the plaintext length */
    {
        uint64_t announced = 0;
        memcpy(&announced, ct + TESS_OFF_PT_LEN_TEST, sizeof announced);
        CHECK(announced == (uint64_t)pt_len);
    }

    /* 1. a 4 GiB announcement must not turn into a 4 GiB allocation */
    {
        uint8_t *lie = (uint8_t *)malloc(ct_len);
        uint64_t huge = 0xffffffffull; /* 4 GiB - 1 */
        CHECK(lie != NULL);
        memcpy(lie, ct, ct_len);
        memcpy(lie + TESS_OFF_PT_LEN_TEST, &huge, sizeof huge);

        tess_open_options_init(&oo);
        oo.recipient_secret = bob_sec;
        before = working_set_kb();
        out = NULL;
        /* the call must fail (the length is part of the authenticated AAD),
         * but it must fail cheaply */
        CHECK(tess_open(lie, ct_len, &oo, &out, &out_len) != TESS_OK);
        after = working_set_kb();
        free(out);

        if (after > before && after - before > MAX_GROWTH_KB) {
            fprintf(stderr,
                    "FAIL %s:%d: hostile pt_len grew the working set by %zu KB\n",
                    __FILE__, __LINE__, after - before);
            return 1;
        }
        free(lie);
    }

    /* 2. the same announcement with UINT64_MAX ("length unknown") is cheap */
    {
        uint8_t *lie = (uint8_t *)malloc(ct_len);
        uint64_t unknown = UINT64_MAX;
        CHECK(lie != NULL);
        memcpy(lie, ct, ct_len);
        memcpy(lie + TESS_OFF_PT_LEN_TEST, &unknown, sizeof unknown);

        tess_open_options_init(&oo);
        oo.recipient_secret = bob_sec;
        before = working_set_kb();
        out = NULL;
        CHECK(tess_open(lie, ct_len, &oo, &out, &out_len) != TESS_OK);
        after = working_set_kb();
        free(out);

        if (after > before && after - before > MAX_GROWTH_KB) {
            fprintf(stderr, "FAIL %s:%d: unknown pt_len grew by %zu KB\n",
                    __FILE__, __LINE__, after - before);
            return 1;
        }
        free(lie);
    }

    /* 3. the dedicated "what is in this message" inspector must be cheap on
     *    the same hostile input (it is what the GUI calls) */
    {
        uint8_t *lie = (uint8_t *)malloc(ct_len);
        uint64_t huge = 0xffffffffull;
        tess_message_info info;
        CHECK(lie != NULL);
        memcpy(lie, ct, ct_len);
        memcpy(lie + TESS_OFF_PT_LEN_TEST, &huge, sizeof huge);

        before = working_set_kb();
        memset(&info, 0, sizeof info);
        (void)tess_inspect(lie, ct_len, &info);
        after = working_set_kb();
        if (after > before && after - before > MAX_GROWTH_KB) {
            fprintf(stderr, "FAIL %s:%d: inspect grew by %zu KB\n", __FILE__,
                    __LINE__, after - before);
            return 1;
        }
        free(lie);
    }

    /* 4. and the honest message still decrypts */
    {
        tess_open_options_init(&oo);
        oo.recipient_secret = bob_sec;
        out = NULL;
        CHECK_ST(tess_open(ct, ct_len, &oo, &out, &out_len), TESS_OK);
        CHECK(bytes_eq(pt, pt_len, out, out_len));
        free(out);
    }

    free(ct);
    free(pt);
    tess_key_free(bob_sec);
    tess_key_free(bob_pub);
    printf("limits: OK\n");
    return 0;
}
