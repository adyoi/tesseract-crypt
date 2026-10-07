/* test_roundtrip.c — seal/open roundtrips for every mode. */
#include "common.h"

static int roundtrip(const uint8_t *pt, size_t pt_len,
                     const tess_key *recip, const tess_key *sender,
                     int sign, const char *pass, uint32_t chunk_size) {
    tess_seal_options so;
    tess_open_options oo;
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    uint8_t *back = NULL;
    size_t back_len = 0;
    int signed_flag = -1;

    tess_seal_options_init(&so);
    so.recipient_public = recip;
    so.sender_secret = sender;
    so.sign = sign;
    so.passphrase = pass;
    so.chunk_size = chunk_size;

    CHECK_ST(tess_seal(pt, pt_len, &so, &ct, &ct_len), TESS_OK);
    CHECK(ct != NULL);
    CHECK(ct_len >= TESS_HEADER_BYTES);

    tess_open_options_init(&oo);
    oo.recipient_secret = recip ? NULL : NULL; /* set below */
    oo.passphrase = pass;
    oo.out_signed = &signed_flag;

    if (recip != NULL) {
        /* recipient secret: derive from the same keypair via public part */
        oo.passphrase = NULL;
    }

    {
        /* open needs the *secret* key; tests pass it in via `recip` when
         * that key is secret. */
        int is_secret = recip != NULL && tess_key_is_secret(recip);
        if (is_secret) {
            oo.recipient_secret = recip;
            oo.passphrase = NULL;
        } else if (pass != NULL) {
            oo.recipient_secret = NULL;
            oo.passphrase = pass;
        } else {
            free(ct);
            return 1;
        }
    }

    CHECK_ST(tess_open(ct, ct_len, &oo, &back, &back_len), TESS_OK);
    CHECK(bytes_eq(pt, pt_len, back, back_len));
    CHECK(signed_flag == (sign ? 1 : 0));

    free(back);
    free(ct);
    return 0;
}

int main(void) {
    tess_key *recip_sec = NULL, *recip_pub = NULL;
    tess_key *send_sec = NULL, *send_pub = NULL;
    uint8_t *msg;

    CHECK(sodium_init() >= 0);
    CHECK_ST(tess_keygen(&recip_sec, &recip_pub), TESS_OK);
    CHECK_ST(tess_keygen(&send_sec, &send_pub), TESS_OK);

    /* --- mode 1: public key, various sizes --- */
    {
        size_t sizes[] = {0, 1, 100, 4095, 4096, 4097, 100000};
        size_t i;
        for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
            uint8_t *data = fill_pattern(sizes[i], (uint8_t)i);
            CHECK(roundtrip(data, sizes[i], recip_sec, send_sec, 1, NULL,
                            4096) == 0);
            free(data);
        }
    }

    /* anonymous + unsigned */
    msg = fill_pattern(10, 7);
    CHECK(roundtrip(msg, 10, recip_sec, NULL, 0, NULL, 0) == 0);
    free(msg);

    /* signed but anonymous encryption (no sender x25519) */
    msg = fill_pattern(10, 9);
    CHECK(roundtrip(msg, 10, recip_sec, send_sec, 1, NULL, 0) == 0);
    free(msg);

    /* --- mode 2: passphrase --- */
    {
        uint8_t *data = fill_pattern(9000, 42);
        CHECK(roundtrip(data, 9000, NULL, send_sec, 1, "s3cret-pass", 4096) ==
              0);
        free(data);
    }

    /* --- multi-chunk with default size --- */
    {
        uint8_t *big = fill_pattern(300000, 3);
        CHECK(roundtrip(big, 300000, recip_sec, send_sec, 1, NULL, 0) == 0);
        free(big);
    }

    tess_key_free(recip_sec);
    tess_key_free(recip_pub);
    tess_key_free(send_sec);
    tess_key_free(send_pub);
    printf("roundtrip: OK\n");
    return 0;
}
