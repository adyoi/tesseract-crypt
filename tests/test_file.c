/* test_file.c — streaming file seal/open, atomicity, tamper rejection. */
#include "common.h"

static uint8_t *read_whole(const char *p, size_t *len) {
    FILE *f = fopen(p, "rb");
    long sz;
    uint8_t *buf;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    buf = (uint8_t *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    buf[sz] = 0;
    *len = (size_t)sz;
    return buf;
}

static int file_exists(const char *p) {
    FILE *f = fopen(p, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

static long file_len(const char *p) {
    FILE *f = fopen(p, "rb");
    long n;
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fclose(f);
    return n;
}

static int files_equal(const char *a, const char *b) {
    uint8_t *ba = NULL, *bb = NULL;
    size_t la = 0, lb = 0;
    int eq;
    ba = read_whole(a, &la);
    bb = read_whole(b, &lb);
    eq = (ba != NULL && bb != NULL) && bytes_eq(ba, la, bb, lb);
    free(ba);
    free(bb);
    return eq;
}

int main(void) {
    tess_key *bob_sec = NULL, *bob_pub = NULL;
    tess_key *alice_sec = NULL, *alice_pub = NULL;
    uint8_t *pattern;
    size_t len = 200000; /* ~4 chunks at 64 KiB */
    tess_seal_file_options so;
    tess_open_file_options oo;

    CHECK(sodium_init() >= 0);
    CHECK_ST(tess_keygen(&bob_sec, &bob_pub), TESS_OK);
    CHECK_ST(tess_keygen(&alice_sec, &alice_pub), TESS_OK);

    pattern = fill_pattern(len, 77);
    {
        FILE *f = fopen("tess_in.bin", "wb");
        CHECK(f != NULL);
        CHECK(fwrite(pattern, 1, len, f) == len);
        fclose(f);
    }

    /* --- signed file roundtrip --- */
    tess_seal_file_options_init(&so);
    so.recipient_public = bob_pub;
    so.sender_secret = alice_sec;
    so.sign = 1;
    CHECK_ST(tess_seal_file("tess_in.bin", "tess_out.bin", &so), TESS_OK);
    CHECK(file_exists("tess_out.bin"));
    CHECK(!file_exists("tess_out.bin.part"));
    CHECK(file_len("tess_out.bin") > (long)len); /* header + tags */

    tess_open_file_options_init(&oo);
    oo.recipient_secret = bob_sec;
    {
        int signed_out = -1;
        oo.out_signed = &signed_out;
        CHECK_ST(tess_open_file("tess_out.bin", "tess_plain.bin", &oo),
                 TESS_OK);
        CHECK(signed_out == 1);
    }
    CHECK(files_equal("tess_in.bin", "tess_plain.bin"));
    CHECK(!file_exists("tess_plain.bin.part"));

    /* --- tampered ciphertext: must fail AND leave no output --- */
    {
        uint8_t *ct = NULL;
        size_t ct_len = 0;
        FILE *f;
        ct = read_whole("tess_out.bin", &ct_len);
        CHECK(ct != NULL);
        ct[ct_len - 1] ^= 0x80;
        f = fopen("tess_bad.bin", "wb");
        CHECK(f != NULL);
        fwrite(ct, 1, ct_len, f);
        fclose(f);
        free(ct);

        remove("tess_plain2.bin");
        tess_open_file_options_init(&oo);
        oo.recipient_secret = bob_sec;
        CHECK(tess_open_file("tess_bad.bin", "tess_plain2.bin", &oo) !=
              TESS_OK);
        CHECK(!file_exists("tess_plain2.bin"));
        CHECK(!file_exists("tess_plain2.bin.part"));
    }

    /* --- wrong required signer: rejected before any output --- */
    {
        tess_key *eve_sec = NULL, *eve_pub = NULL;
        CHECK_ST(tess_keygen(&eve_sec, &eve_pub), TESS_OK);
        tess_open_file_options_init(&oo);
        oo.recipient_secret = bob_sec;
        oo.required_signer = eve_pub;
        remove("tess_plain3.bin");
        CHECK(tess_open_file("tess_out.bin", "tess_plain3.bin", &oo) ==
              TESS_ERR_SIGNER);
        CHECK(!file_exists("tess_plain3.bin"));
        tess_key_free(eve_sec);
        tess_key_free(eve_pub);
    }

    /* --- correct required signer succeeds --- */
    tess_open_file_options_init(&oo);
    oo.recipient_secret = bob_sec;
    oo.required_signer = alice_pub;
    CHECK_ST(tess_open_file("tess_out.bin", "tess_plain4.bin", &oo), TESS_OK);
    CHECK(files_equal("tess_in.bin", "tess_plain4.bin"));

    /* --- unsigned file roundtrip --- */
    tess_seal_file_options_init(&so);
    so.recipient_public = bob_pub;
    so.sign = 0;
    CHECK_ST(tess_seal_file("tess_in.bin", "tess_out2.bin", &so), TESS_OK);
    tess_open_file_options_init(&oo);
    oo.recipient_secret = bob_sec;
    CHECK_ST(tess_open_file("tess_out2.bin", "tess_plain5.bin", &oo),
             TESS_OK);
    CHECK(files_equal("tess_in.bin", "tess_plain5.bin"));

    /* --- empty file roundtrip --- */
    {
        FILE *f = fopen("tess_empty.bin", "wb");
        CHECK(f != NULL);
        fclose(f);
        tess_seal_file_options_init(&so);
        so.recipient_public = bob_pub;
        so.sign = 1;
        so.sender_secret = alice_sec;
        CHECK_ST(tess_seal_file("tess_empty.bin", "tess_eout.bin", &so),
                 TESS_OK);
        tess_open_file_options_init(&oo);
        oo.recipient_secret = bob_sec;
        CHECK_ST(tess_open_file("tess_eout.bin", "tess_eplain.bin", &oo),
                 TESS_OK);
        CHECK(file_len("tess_eplain.bin") == 0);
    }

    /* --- passphrase file roundtrip --- */
    {
        tess_seal_file_options_init(&so);
        so.passphrase = "file-pass";
        CHECK_ST(tess_seal_file("tess_in.bin", "tess_out3.bin", &so), TESS_OK);
        tess_open_file_options_init(&oo);
        oo.passphrase = "wrong-pass";
        remove("tess_plain6.bin");
        CHECK(tess_open_file("tess_out3.bin", "tess_plain6.bin", &oo) !=
              TESS_OK);
        CHECK(!file_exists("tess_plain6.bin"));
        tess_open_file_options_init(&oo);
        oo.passphrase = "file-pass";
        CHECK_ST(tess_open_file("tess_out3.bin", "tess_plain6.bin", &oo),
                 TESS_OK);
        CHECK(files_equal("tess_in.bin", "tess_plain6.bin"));
    }

    /* --- overwriting an existing output file must work (rename semantics) --- */
    {
        FILE *f = fopen("tess_ovr.bin", "wb");
        CHECK(f != NULL);
        fwrite("junk", 1, 4, f);
        fclose(f);
        tess_open_file_options_init(&oo);
        oo.recipient_secret = bob_sec;
        CHECK_ST(tess_open_file("tess_out.bin", "tess_ovr.bin", &oo), TESS_OK);
        CHECK(files_equal("tess_in.bin", "tess_ovr.bin"));
        remove("tess_ovr.bin");
    }

    /* --- cleanup --- */
    remove("tess_in.bin");
    remove("tess_out.bin");
    remove("tess_out2.bin");
    remove("tess_out3.bin");
    remove("tess_eout.bin");
    remove("tess_bad.bin");
    remove("tess_plain.bin");
    remove("tess_plain4.bin");
    remove("tess_plain5.bin");
    remove("tess_plain6.bin");
    remove("tess_eplain.bin");

    free(pattern);
    tess_key_free(bob_sec);
    tess_key_free(bob_pub);
    tess_key_free(alice_sec);
    tess_key_free(alice_pub);
    printf("file: OK\n");
    return 0;
}
