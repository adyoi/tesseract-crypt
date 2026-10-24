/* test_pe.c — PE containers: chunked sealing of large files. */
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
    size_t la = 0, lb = 0;
    uint8_t *ba = read_whole(a, &la);
    uint8_t *bb = read_whole(b, &lb);
    int eq = (ba != NULL && bb != NULL) && bytes_eq(ba, la, bb, lb);
    free(ba);
    free(bb);
    return eq;
}

static void write_pattern_file(const char *path, const uint8_t *buf,
                               size_t len) {
    FILE *f = fopen(path, "wb");
    if (f == NULL) return;
    fwrite(buf, 1, len, f);
    fclose(f);
}

static int has_pe_magic(const char *path) {
    uint8_t m[3] = {0, 0, 0};
    FILE *f = fopen(path, "rb");
    size_t n;
    if (f == NULL) return 0;
    n = fread(m, 1, 3, f);
    fclose(f);
    return n == 3 && m[0] == 't' && m[1] == 's' && m[2] == 'c';
}

/* copy `in` into `out` changing the byte at `offset` by xor `mask` */
static int patch_byte(const char *in, const char *out, long offset,
                      uint8_t mask) {
    size_t len = 0;
    uint8_t *buf = read_whole(in, &len);
    FILE *f;
    if (buf == NULL || offset < 0 || (size_t)offset >= len) {
        free(buf);
        return 0;
    }
    buf[offset] ^= mask;
    f = fopen(out, "wb");
    if (f == NULL) {
        free(buf);
        return 0;
    }
    fwrite(buf, 1, len, f);
    fclose(f);
    free(buf);
    return 1;
}

int main(void) {
    tess_key *bob_sec = NULL, *bob_pub = NULL;
    tess_key *alice_sec = NULL, *alice_pub = NULL;
    tess_pe_options pe;
    tess_seal_file_options so;
    tess_open_file_options oo;
    const size_t len = 3500000; /* > 3 frames at the 1 MiB minimum chunk */
    uint8_t *pattern;

    CHECK(sodium_init() >= 0);
    CHECK_ST(tess_keygen(&bob_sec, &bob_pub), TESS_OK);
    CHECK_ST(tess_keygen(&alice_sec, &alice_pub), TESS_OK);

    pattern = fill_pattern(len, 91);
    CHECK(pattern != NULL);
    write_pattern_file("pe_in.bin", pattern, len);
    CHECK(file_len("pe_in.bin") == (long)len);

    /* --- container with several frames, signed --- */
    tess_pe_options_init(&pe);
    pe.chunk_bytes = TESS_PE_MIN_CHUNK;
    tess_seal_file_options_init(&so);
    so.recipient_public = bob_pub;
    so.sender_secret = alice_sec;
    so.sign = 1;
    CHECK_ST(tess_seal_file_pe("pe_in.bin", "pe_out.bin", &so, &pe), TESS_OK);
    CHECK(file_exists("pe_out.bin"));
    CHECK(!file_exists("pe_out.bin.part"));
    CHECK(tess_is_pe_file("pe_out.bin") == 1);
    CHECK(has_pe_magic("pe_out.bin"));
    CHECK(file_len("pe_out.bin") > (long)len); /* header + tags */

    /* the normal open path auto-detects the container */
    tess_open_file_options_init(&oo);
    oo.recipient_secret = bob_sec;
    {
        int signed_out = -1;
        oo.out_signed = &signed_out;
        CHECK_ST(tess_open_file("pe_out.bin", "pe_plain.bin", &oo), TESS_OK);
        CHECK(signed_out == 1);
    }
    CHECK(files_equal("pe_in.bin", "pe_plain.bin"));

    /* explicit unpack matches too */
    tess_open_file_options_init(&oo);
    oo.recipient_secret = bob_sec;
    CHECK_ST(tess_open_file_pe("pe_out.bin", "pe_plain2.bin", &oo), TESS_OK);
    CHECK(files_equal("pe_in.bin", "pe_plain2.bin"));

    /* --- armored frames --- */
    pe.armor = 1;
    CHECK_ST(tess_seal_file_pe("pe_in.bin", "pe_arm.bin", &so, &pe), TESS_OK);
    CHECK(tess_is_pe_file("pe_arm.bin") == 1);
    tess_open_file_options_init(&oo);
    oo.recipient_secret = bob_sec;
    CHECK_ST(tess_open_file("pe_arm.bin", "pe_arm_plain.bin", &oo), TESS_OK);
    CHECK(files_equal("pe_in.bin", "pe_arm_plain.bin"));

    /* --- multi recipient --- */
    {
        const tess_key *recips[2];
        tess_seal_file_options mo;
        recips[0] = bob_pub;
        recips[1] = alice_pub;
        tess_seal_file_options_init(&mo);
        mo.recipients = recips;
        mo.recipient_count = 2;
        mo.passphrase = NULL;
        pe.armor = 0;
        CHECK_ST(tess_seal_file_pe("pe_in.bin", "pe_multi.bin", &mo, &pe),
                 TESS_OK);
        tess_open_file_options_init(&oo);
        oo.recipient_secret = alice_sec;
        CHECK_ST(tess_open_file("pe_multi.bin", "pe_multi_plain.bin", &oo),
                 TESS_OK);
        CHECK(files_equal("pe_in.bin", "pe_multi_plain.bin"));
    }

    /* --- passphrase container --- */
    {
        tess_seal_file_options po;
        tess_seal_file_options_init(&po);
        po.passphrase = "pe-pass";
        CHECK_ST(tess_seal_file_pe("pe_in.bin", "pe_pass.bin", &po, &pe),
                 TESS_OK);
        tess_open_file_options_init(&oo);
        oo.passphrase = "wrong";
        remove("pe_pass_bad.bin");
        CHECK(tess_open_file("pe_pass.bin", "pe_pass_bad.bin", &oo) != TESS_OK);
        CHECK(!file_exists("pe_pass_bad.bin"));
        CHECK(!file_exists("pe_pass_bad.bin.part"));
        tess_open_file_options_init(&oo);
        oo.passphrase = "pe-pass";
        CHECK_ST(tess_open_file("pe_pass.bin", "pe_pass_plain.bin", &oo),
                 TESS_OK);
        CHECK(files_equal("pe_in.bin", "pe_pass_plain.bin"));
    }

    /* --- empty file --- */
    {
        FILE *f = fopen("pe_empty.bin", "wb");
        CHECK(f != NULL);
        fclose(f);
        tess_seal_file_options_init(&so);
        so.recipient_public = bob_pub;
        CHECK_ST(tess_seal_file_pe("pe_empty.bin", "pe_empty_out.bin", &so,
                                   &pe),
                 TESS_OK);
        CHECK(tess_is_pe_file("pe_empty_out.bin") == 1);
        tess_open_file_options_init(&oo);
        oo.recipient_secret = bob_sec;
        CHECK_ST(tess_open_file("pe_empty_out.bin", "pe_empty_plain.bin", &oo),
                 TESS_OK);
        CHECK(file_len("pe_empty_plain.bin") == 0);
    }

    /* --- a flipped ciphertext byte is rejected, no output at all --- */
    {
        const long last = file_len("pe_out.bin") - 1;
        CHECK(last > 20);
        CHECK(patch_byte("pe_out.bin", "pe_bad.bin", last, 0x01));
        tess_open_file_options_init(&oo);
        oo.recipient_secret = bob_sec;
        remove("pe_bad_plain.bin");
        CHECK(tess_open_file("pe_bad.bin", "pe_bad_plain.bin", &oo) != TESS_OK);
        CHECK(!file_exists("pe_bad_plain.bin"));
        CHECK(!file_exists("pe_bad_plain.bin.part"));
    }

    /* --- a truncated container is rejected --- */
    {
        size_t full = 0;
        uint8_t *buf = read_whole("pe_out.bin", &full);
        FILE *f;
        CHECK(buf != NULL);
        CHECK(full > 100);
        f = fopen("pe_trunc.bin", "wb");
        CHECK(f != NULL);
        fwrite(buf, 1, full - 40, f);
        fclose(f);
        free(buf);
        tess_open_file_options_init(&oo);
        oo.recipient_secret = bob_sec;
        remove("pe_trunc_plain.bin");
        CHECK(tess_open_file("pe_trunc.bin", "pe_trunc_plain.bin", &oo) !=
              TESS_OK);
        CHECK(!file_exists("pe_trunc_plain.bin"));
    }

    /* --- a wrong announced size is rejected --- */
    {
        size_t full = 0;
        uint8_t *buf = read_whole("pe_out.bin", &full);
        FILE *f;
        CHECK(buf != NULL);
        CHECK(full > 20);
        buf[5] ^= 0x01; /* the low byte of the announced plaintext size */
        f = fopen("pe_size.bin", "wb");
        CHECK(f != NULL);
        fwrite(buf, 1, full, f);
        fclose(f);
        free(buf);
        tess_open_file_options_init(&oo);
        oo.recipient_secret = bob_sec;
        remove("pe_size_plain.bin");
        CHECK(tess_open_file("pe_size.bin", "pe_size_plain.bin", &oo) !=
              TESS_OK);
        CHECK(!file_exists("pe_size_plain.bin"));
    }

    /* --- a non-container is not mistaken for one --- */
    CHECK(tess_is_pe_file("pe_in.bin") == 0);

    remove("pe_in.bin");
    remove("pe_out.bin");
    remove("pe_arm.bin");
    remove("pe_multi.bin");
    remove("pe_pass.bin");
    remove("pe_empty.bin");
    remove("pe_empty_out.bin");
    remove("pe_bad.bin");
    remove("pe_trunc.bin");
    remove("pe_size.bin");
    remove("pe_plain.bin");
    remove("pe_plain2.bin");
    remove("pe_arm_plain.bin");
    remove("pe_multi_plain.bin");
    remove("pe_pass_plain.bin");
    remove("pe_empty_plain.bin");

    free(pattern);
    tess_key_free(bob_sec);
    tess_key_free(bob_pub);
    tess_key_free(alice_sec);
    tess_key_free(alice_pub);
    printf("pe: OK\n");
    return 0;
}
