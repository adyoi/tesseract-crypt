/* test_tamper.c — bit flips, truncation, splice, wrong keys must fail. */
#include "common.h"

int main(void) {
    tess_key *bob_sec = NULL, *bob_pub = NULL;
    tess_key *alice_sec = NULL, *alice_pub = NULL;
    tess_key *eve_sec = NULL, *eve_pub = NULL;
    uint8_t *pt = NULL;
    size_t pt_len = 20000;
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    tess_seal_options so;
    tess_open_options oo;
    uint8_t *out = NULL;
    size_t out_len = 0;
    size_t i;

    CHECK(sodium_init() >= 0);
    CHECK_ST(tess_keygen(&bob_sec, &bob_pub), TESS_OK);
    CHECK_ST(tess_keygen(&alice_sec, &alice_pub), TESS_OK);
    CHECK_ST(tess_keygen(&eve_sec, &eve_pub), TESS_OK);

    pt = fill_pattern(pt_len, 11);

    tess_seal_options_init(&so);
    so.recipient_public = bob_pub;
    so.sender_secret = alice_sec;
    so.sign = 1;
    so.chunk_size = 4096;
    CHECK_ST(tess_seal(pt, pt_len, &so, &ct, &ct_len), TESS_OK);

    /* baseline: correct decryption works */
    tess_open_options_init(&oo);
    oo.recipient_secret = bob_sec;
    CHECK_ST(tess_open(ct, ct_len, &oo, &out, &out_len), TESS_OK);
    CHECK(bytes_eq(pt, pt_len, out, out_len));
    free(out);
    out = NULL;

    /* 1. flipping any single byte of the ciphertext must fail */
    for (i = TESS_HEADER_BYTES; i < ct_len; i += (ct_len - TESS_HEADER_BYTES) / 17 + 1) {
        uint8_t saved = ct[i];
        ct[i] = (uint8_t)(saved ^ 0x40);
        tess_open_options_init(&oo);
        oo.recipient_secret = bob_sec;
        out = NULL;
        CHECK(tess_open(ct, ct_len, &oo, &out, &out_len) != TESS_OK);
        free(out);
        out = NULL;
        ct[i] = saved;
    }

    /* 2. flipping header bytes (salt, nonce, chunk size...) must fail */
    {
        size_t header_offsets[] = {8, 40, 72, 136, 200, 228, 252, 256};
        for (i = 0; i < sizeof header_offsets / sizeof header_offsets[0]; i++) {
            uint8_t saved = ct[header_offsets[i]];
            ct[header_offsets[i]] = (uint8_t)(saved ^ 0x01);
            tess_open_options_init(&oo);
            oo.recipient_secret = bob_sec;
            out = NULL;
            CHECK(tess_open(ct, ct_len, &oo, &out, &out_len) != TESS_OK);
            free(out);
            out = NULL;
            ct[header_offsets[i]] = saved;
        }
    }

    /* 3. truncation (dropping the last chunk) must fail */
    {
        uint32_t last_len = 0;
        size_t cut = 0;
        /* walk chunks to find the second-to-last boundary */
        size_t pos = TESS_HEADER_BYTES;
        size_t prev_end = TESS_HEADER_BYTES;
        while (pos + 4 < ct_len) {
            uint32_t cl = (uint32_t)ct[pos] | ((uint32_t)ct[pos + 1] << 8) |
                          ((uint32_t)ct[pos + 2] << 16) |
                          ((uint32_t)ct[pos + 3] << 24);
            prev_end = pos;
            pos += 4 + cl;
            if (pos >= ct_len) break;
        }
        (void)last_len;
        cut = prev_end;
        tess_open_options_init(&oo);
        oo.recipient_secret = bob_sec;
        out = NULL;
        CHECK(tess_open(ct, cut, &oo, &out, &out_len) != TESS_OK);
        free(out);
        out = NULL;
    }

    /* 4. wrong recipient key must fail */
    tess_open_options_init(&oo);
    oo.recipient_secret = eve_sec;
    out = NULL;
    CHECK(tess_open(ct, ct_len, &oo, &out, &out_len) != TESS_OK);
    free(out);
    out = NULL;

    /* 5. required signer mismatch must be rejected */
    tess_open_options_init(&oo);
    oo.recipient_secret = bob_sec;
    oo.required_signer = alice_pub;
    out = NULL;
    CHECK_ST(tess_open(ct, ct_len, &oo, &out, &out_len), TESS_OK);
    free(out);
    out = NULL;

    tess_open_options_init(&oo);
    oo.recipient_secret = bob_sec;
    oo.required_signer = eve_pub; /* wrong identity */
    out = NULL;
    CHECK_ST(tess_open(ct, ct_len, &oo, &out, &out_len), TESS_ERR_SIGNER);
    free(out);
    out = NULL;

    /* 6. garbage input must be rejected */
    {
        uint8_t junk[300];
        memset(junk, 0xa5, sizeof junk);
        tess_open_options_init(&oo);
        oo.recipient_secret = bob_sec;
        out = NULL;
        CHECK(tess_open(junk, sizeof junk, &oo, &out, &out_len) != TESS_OK);
        free(out);
        out = NULL;
    }

    /* 7. passphrase mode: wrong passphrase must fail */
    {
        uint8_t *ct2 = NULL;
        size_t ct2_len = 0;
        tess_seal_options_init(&so);
        so.passphrase = "correct horse";
        so.chunk_size = 4096;
        CHECK_ST(tess_seal(pt, 512, &so, &ct2, &ct2_len), TESS_OK);

        tess_open_options_init(&oo);
        oo.passphrase = "battery staple";
        out = NULL;
        CHECK(tess_open(ct2, ct2_len, &oo, &out, &out_len) != TESS_OK);
        free(out);
        out = NULL;

        tess_open_options_init(&oo);
        oo.passphrase = "correct horse";
        out = NULL;
        CHECK_ST(tess_open(ct2, ct2_len, &oo, &out, &out_len), TESS_OK);
        CHECK(bytes_eq(pt, 512, out, out_len));
        free(out);
        out = NULL;
        free(ct2);
    }

    free(ct);
    free(pt);
    tess_key_free(bob_sec);
    tess_key_free(bob_pub);
    tess_key_free(alice_sec);
    tess_key_free(alice_pub);
    tess_key_free(eve_sec);
    tess_key_free(eve_pub);
    printf("tamper: OK\n");
    return 0;
}
