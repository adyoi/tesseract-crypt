/* test_rekey.c — rekey functionality tests. */
#include "common.h"

int main(void) {
    tess_key *a_s = NULL, *a_p = NULL;
    tess_key *b_s = NULL, *b_p = NULL;
    tess_key *c_s = NULL, *c_p = NULL;
    const tess_key *recips1[1];
    const tess_key *recips2[2];
    uint8_t *pt = NULL;
    uint8_t *ct = NULL, *ct2 = NULL, *out = NULL;
    size_t ct_len = 0, ct2_len = 0, out_len = 0;
    tess_seal_options so;
    tess_open_options oo;
    tess_message_info info;

    CHECK(sodium_init() >= 0);
    CHECK_ST(tess_keygen(&a_s, &a_p), TESS_OK);
    CHECK_ST(tess_keygen(&b_s, &b_p), TESS_OK);
    CHECK_ST(tess_keygen(&c_s, &c_p), TESS_OK);

    recips1[0] = a_p;
    recips2[0] = b_p;
    recips2[1] = c_p;

    pt = fill_pattern(10000, 0x55);
    CHECK(pt != NULL);

    /* Seal to A */
    tess_seal_options_init(&so);
    so.recipient_public = a_p;
    CHECK_ST(tess_seal(pt, 10000, &so, &ct, &ct_len), TESS_OK);

    /* Rekey from A to B and C (multi-recipient) */
    tess_open_options_init(&oo);
    oo.recipient_secret = a_s;

    tess_seal_options_init(&so);
    so.recipients = recips2;
    so.recipient_count = 2;
    CHECK_ST(tess_rekey(ct, ct_len, &oo, &so, &ct2, &ct2_len), TESS_OK);

    /* B can open */
    tess_open_options_init(&oo);
    oo.recipient_secret = b_s;
    CHECK_ST(tess_open(ct2, ct2_len, &oo, &out, &out_len), TESS_OK);
    CHECK(out_len == 10000);
    CHECK(bytes_eq(out, out_len, pt, 10000));
    tess_free(out);
    out = NULL;

    /* C can open */
    tess_open_options_init(&oo);
    oo.recipient_secret = c_s;
    CHECK_ST(tess_open(ct2, ct2_len, &oo, &out, &out_len), TESS_OK);
    CHECK(bytes_eq(out, out_len, pt, 10000));
    tess_free(out);
    out = NULL;

    /* A should not be able to open rekeyed ciphertext (not recipient anymore) */
    tess_open_options_init(&oo);
    oo.recipient_secret = a_s;
    CHECK_ST(tess_open(ct2, ct2_len, &oo, &out, &out_len), TESS_ERR_RECIPIENT);

    tess_free(ct);
    tess_free(ct2);
    free(pt);
    tess_key_free(a_s);
    tess_key_free(a_p);
    tess_key_free(b_s);
    tess_key_free(b_p);
    tess_key_free(c_s);
    tess_key_free(c_p);

    return 0;
}
