/* test_multi.c — multi-recipient messages (wire format version 2).
 *
 * Covers: sealing to N recipients (signed), every recipient opening the
 * message, rejection of non-recipients, block tampering, option validation,
 * backward compatibility of the v1 path and a streaming file round-trip. */
#include "common.h"

static int write_file(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (f == NULL) return 0;
    if (fwrite(buf, 1, len, f) != len) {
        fclose(f);
        return 0;
    }
    return fclose(f) == 0;
}

static int read_file(const char *path, uint8_t *buf, size_t *len, size_t cap) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return 0;
    *len = fread(buf, 1, cap, f);
    fclose(f);
    return 1;
}

int main(void) {
    tess_key *a_s = NULL, *a_p = NULL;
    tess_key *b_s = NULL, *b_p = NULL;
    tess_key *c_s = NULL, *c_p = NULL;
    tess_key *d_s = NULL, *d_p = NULL;
    tess_key *snd_s = NULL, *snd_p = NULL;
    const tess_key *recips[3];
    const tess_key *single[1];
    uint8_t *pt = NULL;
    uint8_t *ct = NULL, *out = NULL;
    size_t ct_len = 0, out_len = 0, n;
    tess_seal_options so;
    tess_open_options oo;
    tess_message_info info;

    CHECK(sodium_init() >= 0);
    CHECK_ST(tess_keygen(&a_s, &a_p), TESS_OK);
    CHECK_ST(tess_keygen(&b_s, &b_p), TESS_OK);
    CHECK_ST(tess_keygen(&c_s, &c_p), TESS_OK);
    CHECK_ST(tess_keygen(&d_s, &d_p), TESS_OK);
    CHECK_ST(tess_keygen(&snd_s, &snd_p), TESS_OK);

    recips[0] = a_p;
    recips[1] = b_p;
    recips[2] = c_p;
    single[0] = a_p;

    pt = fill_pattern(70000, 0x42); /* spans several 64 KiB chunks */

    /* ---- seal for three recipients, signed ---- */
    tess_seal_options_init(&so);
    so.recipients = recips;
    so.recipient_count = 3;
    so.sender_secret = snd_s;
    so.sign = 1;
    CHECK_ST(tess_seal(pt, 70000, &so, &ct, &ct_len), TESS_OK);

    CHECK_ST(tess_inspect(ct, ct_len, &info), TESS_OK);
    CHECK(info.version == 2);
    CHECK(info.recipient_count == 3);
    CHECK(info.signed_flag == 1);

    /* every recipient can open it */
    {
        const tess_key *keys[3] = {a_s, b_s, c_s};
        int i;
        for (i = 0; i < 3; i++) {
            int signed_flag = 0;
            tess_open_options_init(&oo);
            oo.recipient_secret = keys[i];
            oo.out_signed = &signed_flag;
            out = NULL;
            CHECK_ST(tess_open(ct, ct_len, &oo, &out, &out_len), TESS_OK);
            CHECK(out_len == 70000);
            CHECK(bytes_eq(out, out_len, pt, 70000));
            CHECK(signed_flag == 1);
            free(out);
            out = NULL;
        }
    }

    /* a non-recipient must be rejected explicitly */
    tess_open_options_init(&oo);
    oo.recipient_secret = d_s;
    CHECK_ST(tess_open(ct, ct_len, &oo, &out, &out_len), TESS_ERR_RECIPIENT);

    /* ---- tampering with the key blocks ---- */
    {
        uint8_t *tam = (uint8_t *)malloc(ct_len);
        CHECK(tam != NULL);
        /* flipped recipient pk: no block matches alice any more */
        memcpy(tam, ct, ct_len);
        tam[264] ^= 0x01;
        tess_open_options_init(&oo);
        oo.recipient_secret = a_s;
        CHECK_ST(tess_open(tam, ct_len, &oo, &out, &out_len),
                 TESS_ERR_RECIPIENT);
        /* flipped sealed-key byte: block found, unwrap fails */
        memcpy(tam, ct, ct_len);
        tam[264 + 32] ^= 0x01;
        CHECK_ST(tess_open(tam, ct_len, &oo, &out, &out_len),
                 TESS_ERR_CRYPTO);
        /* truncated block segment */
        CHECK_ST(tess_open(tam, 264 + 3 * 80 - 1, &oo, &out, &out_len),
                 TESS_ERR_FORMAT);
        free(tam);
    }

    /* ---- option validation ---- */
    tess_seal_options_init(&so);
    so.recipients = recips;
    so.recipient_count = 0;
    CHECK_ST(tess_seal(pt, 16, &so, &ct, &ct_len), TESS_ERR_INVALID_ARG);

    so.recipient_count = 3;
    so.recipient_public = a_p; /* both fields: ambiguous */
    CHECK_ST(tess_seal(pt, 16, &so, &ct, &ct_len), TESS_ERR_INVALID_ARG);

    so.recipient_public = NULL;
    so.passphrase = "hunter2"; /* multi-recipient + passphrase: ambiguous */
    CHECK_ST(tess_seal(pt, 16, &so, &ct, &ct_len), TESS_ERR_INVALID_ARG);

    so.passphrase = NULL;
    so.recipient_count = (size_t)TESS_MAX_RECIPIENTS + 1; /* must not alloc */
    CHECK_ST(tess_seal(pt, 16, &so, &ct, &ct_len), TESS_ERR_INVALID_ARG);

    /* ---- single recipient still emits v1 (backward compatible) ---- */
    tess_seal_options_init(&so);
    so.recipient_public = a_p;
    CHECK_ST(tess_seal(pt, 70000, &so, &ct, &ct_len), TESS_OK);
    CHECK_ST(tess_inspect(ct, ct_len, &info), TESS_OK);
    CHECK(info.version == 1);
    CHECK(info.recipient_count == 1);
    tess_open_options_init(&oo);
    oo.recipient_secret = a_s;
    CHECK_ST(tess_open(ct, ct_len, &oo, &out, &out_len), TESS_OK);
    CHECK(bytes_eq(out, out_len, pt, 70000));
    free(out);
    out = NULL;
    free(ct);
    ct = NULL;

    /* ---- array API with a single key still selects format v2 ---- */
    tess_seal_options_init(&so);
    so.recipients = single;
    so.recipient_count = 1;
    CHECK_ST(tess_seal(pt, 70000, &so, &ct, &ct_len), TESS_OK);
    CHECK_ST(tess_inspect(ct, ct_len, &info), TESS_OK);
    CHECK(info.version == 2);
    CHECK(info.recipient_count == 1);
    tess_open_options_init(&oo);
    oo.recipient_secret = a_s;
    CHECK_ST(tess_open(ct, ct_len, &oo, &out, &out_len), TESS_OK);
    CHECK(bytes_eq(out, out_len, pt, 70000));
    free(out);
    out = NULL;
    free(ct);
    ct = NULL;

    /* ---- streaming file round-trip to three recipients ---- */
    {
        tess_seal_file_options fo;
        tess_open_file_options fo2;
        uint8_t *readback = (uint8_t *)malloc(70000);
        int signed_flag = 0;

        CHECK(readback != NULL);
        CHECK(write_file("test_multi_in.bin", pt, 70000));
        tess_seal_file_options_init(&fo);
        fo.recipients = recips;
        fo.recipient_count = 3;
        fo.sender_secret = snd_s;
        fo.sign = 1;
        CHECK_ST(tess_seal_file("test_multi_in.bin", "test_multi_out.bin", &fo),
                 TESS_OK);
        /* carol opens it */
        tess_open_file_options_init(&fo2);
        fo2.recipient_secret = c_s;
        fo2.out_signed = &signed_flag;
        CHECK_ST(tess_open_file("test_multi_out.bin", "test_multi_pt.bin",
                                &fo2),
                 TESS_OK);
        CHECK(signed_flag == 1);
        n = 0;
        CHECK(read_file("test_multi_pt.bin", readback, &n, 70000));
        CHECK(n == 70000);
        CHECK(bytes_eq(readback, n, pt, 70000));
        /* a stranger must fail without leaving output behind */
        tess_open_file_options_init(&fo2);
        fo2.recipient_secret = d_s;
        CHECK_ST(tess_open_file("test_multi_out.bin", "test_multi_pt.bin",
                                &fo2),
                 TESS_ERR_RECIPIENT);
        free(readback);
        remove("test_multi_in.bin");
        remove("test_multi_out.bin");
        remove("test_multi_pt.bin");
    }

    free(pt);
    free(ct);
    tess_key_free(a_s);
    tess_key_free(a_p);
    tess_key_free(b_s);
    tess_key_free(b_p);
    tess_key_free(c_s);
    tess_key_free(c_p);
    tess_key_free(d_s);
    tess_key_free(d_p);
    tess_key_free(snd_s);
    tess_key_free(snd_p);
    printf("multi: OK\n");
    return 0;
}
