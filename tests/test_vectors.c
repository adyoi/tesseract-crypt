/* test_vectors.c — known-answer tests (KAT) for format v1.
 *
 * Three vector families, all frozen constants:
 *   1. header    — crafted 264-byte headers vs. the table in docs/format.html
 *   2. armor     — exact PEM-like encoding of a fixed 9-byte input
 *   3. signature — a fixture key + message whose Ed25519ph signature is
 *                  deterministic (tests/fixtures/kat.{key,pub,msg,sig},
 *                  generated once with tesseract-crypt 0.1.0)
 *
 * Changing the wire format or the crypto plumbing must NOT change these
 * outputs — if a vector drifts, the format broke.
 */
#include "common.h"

#define FIX(p) TESS_FIXTURES_DIR "/" p

/* ---- little-endian writers (wire format is LE) ---------------------- */
static void wr_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void wr_u64(uint8_t *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* Craft a valid signed public-key header per docs/format.html.  The sender
 * identity is x_pk = 0x00..0x1f and ed_pk = 0x20..0x3f so the inspect
 * fingerprint (BLAKE2b-128 over x_pk||ed_pk) is a fixed known value. */
static void mk_header(uint8_t h[264]) {
    size_t i;
    memset(h, 0, 264);
    memcpy(h + 0, "TSCR", 4);
    h[4] = 1;      /* version                */
    h[5] = 1;      /* suite 1                */
    h[6] = 1;      /* mode: public-key       */
    h[7] = 0x01;   /* flags: signed          */
    for (i = 0; i < 32; i++) {
        h[8 + i] = (uint8_t)(0xA0 + i);   /* eph pk       */
        h[40 + i] = (uint8_t)(0x50 + i);  /* recipient pk */
        h[72 + i] = (uint8_t)i;           /* sender x pk  */
        h[104 + i] = (uint8_t)(0x20 + i); /* sender ed pk */
    }
    for (i = 0; i < 64; i++) h[136 + i] = (uint8_t)(0xE0 ^ i); /* signature */
    for (i = 0; i < 16; i++) h[200 + i] = (uint8_t)(0xF0 + i); /* salt      */
    wr_u32(h + 216, 3);                  /* argon2 ops                */
    wr_u64(h + 220, 268435456ull);       /* argon2 mem (256 MiB)      */
    for (i = 0; i < 24; i++) h[228 + i] = (uint8_t)(0x11 * (i + 1)); /* nonce */
    wr_u32(h + 252, 65536u);             /* chunk size                */
    wr_u64(h + 256, 11ull);              /* plaintext length          */
}

/* fingerprint of x_pk = 0x00..0x1f || ed_pk = 0x20..0x3f */
#define FP_SENDER "59059895958b8a56277edb046df67166"
/* fingerprint of an all-zero sender identity */
#define FP_ZERO "532fe82fc5db1ef54fd5be9ba44b69b4"
/* fixture key fingerprint (tesseract-crypt 0.1.0 keygen) */
#define FP_FIXTURE "648d4129d40d2000da970ffbd049e75f"

static uint8_t KAT_MSG[] = "tesseract-kat-v1";
#define KAT_MSG_LEN (sizeof KAT_MSG - 1)

int main(void) {
    uint8_t h[264];
    tess_message_info info;

    CHECK(sodium_init() >= 0);

    /* ---------------- 1. header vectors ---------------- */
    mk_header(h);
    CHECK_ST(tess_inspect(h, sizeof h, &info), TESS_OK);
    CHECK(info.version == 1);
    CHECK(info.suite == 1);
    CHECK(info.mode == TESS_MODE_PUBLICKEY);
    CHECK(info.flags == TESS_FLAG_SIGNED);
    CHECK(info.signed_flag == 1);
    CHECK(info.chunk_size == 65536u);
    CHECK(info.plaintext_len == 11u);
    CHECK(info.has_sender == 1);
    CHECK(strcmp(info.fingerprint, FP_SENDER) == 0);

    /* truncation / NULL arguments */
    CHECK_ST(tess_inspect(h, 263, &info), TESS_ERR_FORMAT);
    CHECK_ST(tess_inspect(NULL, 264, &info), TESS_ERR_INVALID_ARG);
    CHECK_ST(tess_inspect(h, 264, NULL), TESS_ERR_INVALID_ARG);

    /* magic / version / suite */
    mk_header(h);
    h[0] = 'X';
    CHECK_ST(tess_inspect(h, 264, &info), TESS_ERR_FORMAT);
    mk_header(h);
    h[4] = 2;
    CHECK_ST(tess_inspect(h, 264, &info), TESS_ERR_UNSUPPORTED);
    mk_header(h);
    h[5] = 2;
    CHECK_ST(tess_inspect(h, 264, &info), TESS_ERR_UNSUPPORTED);

    /* mode / flags */
    mk_header(h);
    h[6] = 3;
    CHECK_ST(tess_inspect(h, 264, &info), TESS_ERR_FORMAT);
    mk_header(h);
    h[7] = 0x02; /* unknown flag bit */
    CHECK_ST(tess_inspect(h, 264, &info), TESS_ERR_FORMAT);

    /* chunk bounds */
    mk_header(h);
    wr_u32(h + 252, 4095u); /* TESS_MIN_CHUNK - 1 */
    CHECK_ST(tess_inspect(h, 264, &info), TESS_ERR_FORMAT);
    mk_header(h);
    wr_u32(h + 252, 16777217u); /* TESS_MAX_CHUNK + 1 */
    CHECK_ST(tess_inspect(h, 264, &info), TESS_ERR_FORMAT);

    /* signed flag without a signer key */
    mk_header(h);
    memset(h + 104, 0, 32);
    CHECK_ST(tess_inspect(h, 264, &info), TESS_ERR_FORMAT);

    /* passphrase header: valid */
    mk_header(h);
    h[6] = TESS_MODE_PASSPHRASE;
    h[7] = 0;
    wr_u32(h + 216, 3);
    wr_u64(h + 220, 268435456ull);
    CHECK_ST(tess_inspect(h, 264, &info), TESS_OK);
    CHECK(info.mode == TESS_MODE_PASSPHRASE);
    CHECK(info.signed_flag == 0);
    CHECK(strcmp(info.fingerprint, FP_SENDER) == 0);

    /* passphrase header: anonymous (zero sender identity) */
    mk_header(h);
    h[6] = TESS_MODE_PASSPHRASE;
    h[7] = 0;
    memset(h + 72, 0, 32);
    memset(h + 104, 0, 32);
    wr_u32(h + 216, 3);
    wr_u64(h + 220, 268435456ull);
    CHECK_ST(tess_inspect(h, 264, &info), TESS_OK);
    CHECK(info.has_sender == 0);
    CHECK(strcmp(info.fingerprint, FP_ZERO) == 0);

    /* Argon2id bounds (anti-DoS), mode 2 only */
    mk_header(h);
    h[6] = TESS_MODE_PASSPHRASE;
    h[7] = 0;
    wr_u32(h + 216, 0);
    CHECK_ST(tess_inspect(h, 264, &info), TESS_ERR_FORMAT);
    mk_header(h);
    h[6] = TESS_MODE_PASSPHRASE;
    h[7] = 0;
    wr_u32(h + 216, 17); /* TESS_ARGON_MAX_OPS + 1 */
    CHECK_ST(tess_inspect(h, 264, &info), TESS_ERR_FORMAT);
    mk_header(h);
    h[6] = TESS_MODE_PASSPHRASE;
    h[7] = 0;
    wr_u32(h + 216, 3);
    wr_u64(h + 220, 32768ull); /* 32 KiB < minimum */
    CHECK_ST(tess_inspect(h, 264, &info), TESS_ERR_FORMAT);
    mk_header(h);
    h[6] = TESS_MODE_PASSPHRASE;
    h[7] = 0;
    wr_u32(h + 216, 3);
    wr_u64(h + 220, 5368709120ull); /* 5 GiB > cap */
    CHECK_ST(tess_inspect(h, 264, &info), TESS_ERR_FORMAT);

    /* ---------------- 2. armor vectors ---------------- */
    {
        char *arm = NULL;
        uint8_t *back = NULL;
        size_t back_len = 0;
        static const char want[] =
            "-----BEGIN TESSERACT MESSAGE-----\n"
            "VGVzc2VyYWN0\n"
            "-----END TESSERACT MESSAGE-----\n";

        CHECK_ST(tess_armor((const uint8_t *)"Tesseract", 9,
                            "TESSERACT MESSAGE", &arm),
                 TESS_OK);
        CHECK(strcmp(arm, want) == 0);
        CHECK_ST(tess_dearmor(arm, &back, &back_len), TESS_OK);
        CHECK(back_len == 9);
        CHECK(memcmp(back, "Tesseract", 9) == 0);
        free(back);
        free(arm);
    }
    {
        uint8_t *junk = NULL;
        size_t junk_len = 0;
        CHECK_ST(tess_dearmor("no armor here\n", &junk, &junk_len),
                 TESS_ERR_FORMAT);
        CHECK_ST(tess_dearmor("-----BEGIN TESSERACT MESSAGE-----\nAAAA\n",
                              &junk, &junk_len),
                 TESS_ERR_FORMAT); /* missing END marker */
        CHECK_ST(tess_dearmor("-----END TESSERACT MESSAGE-----\n", &junk,
                              &junk_len),
                 TESS_ERR_FORMAT); /* missing BEGIN marker */
    }

    /* ---------------- 3. signature fixture ---------------- */
    {
        tess_key *sec = NULL;
        tess_key *pub = NULL;
        tess_key *parsed = NULL;
        char fp[TESS_FINGERPRINT_HEX + 1];
        char fp2[TESS_FINGERPRINT_HEX + 1];
        char *serialized = NULL;
        char sigtext[512];
        uint8_t sig[TESS_SIGNATURE_BYTES];
        uint8_t *filesig = NULL;
        size_t filesig_len = 0;
        FILE *f;
        size_t n;

        CHECK_ST(tess_key_load(FIX("kat.key"), NULL, &sec), TESS_OK);
        CHECK_ST(tess_key_fingerprint(sec, fp), TESS_OK);
        CHECK(strcmp(fp, FP_FIXTURE) == 0);

        /* serialize → parse round-trip keeps the identity */
        CHECK_ST(tess_key_serialize(sec, &serialized), TESS_OK);
        CHECK_ST(tess_key_parse(serialized, NULL, &parsed), TESS_OK);
        CHECK_ST(tess_key_fingerprint(parsed, fp2), TESS_OK);
        CHECK(strcmp(fp2, FP_FIXTURE) == 0);

        /* Ed25519ph is deterministic: the API must reproduce the exact
         * signature the CLI wrote to tests/fixtures/kat.sig */
        CHECK_ST(tess_sign(KAT_MSG, KAT_MSG_LEN, sec, sig), TESS_OK);
        f = fopen(FIX("kat.sig"), "rb");
        CHECK(f != NULL);
        n = fread(sigtext, 1, sizeof sigtext - 1, f);
        fclose(f);
        sigtext[n] = '\0';
        CHECK_ST(tess_dearmor(sigtext, &filesig, &filesig_len), TESS_OK);
        CHECK(filesig_len == TESS_SIGNATURE_BYTES);
        CHECK(bytes_eq(sig, TESS_SIGNATURE_BYTES, filesig, filesig_len));

        CHECK_ST(tess_key_get_public(sec, &pub), TESS_OK);
        CHECK_ST(tess_verify(KAT_MSG, KAT_MSG_LEN, pub, sig), TESS_OK);
        CHECK_ST(tess_verify(KAT_MSG, KAT_MSG_LEN, pub, filesig), TESS_OK);
        CHECK_ST(tess_verify_file(FIX("kat.msg"), pub, filesig), TESS_OK);

        /* one flipped bit anywhere must fail */
        sig[0] ^= 0x01;
        CHECK_ST(tess_verify(KAT_MSG, KAT_MSG_LEN, pub, sig),
                 TESS_ERR_SIGNATURE);
        sig[0] ^= 0x01;
        KAT_MSG[0] = 'T'; /* "tesseract..." -> "Tesseract..." */
        CHECK_ST(tess_verify(KAT_MSG, KAT_MSG_LEN, pub, sig),
                 TESS_ERR_SIGNATURE);
        KAT_MSG[0] = 't';

        free(filesig);
        free(serialized);
        tess_key_free(pub);
        tess_key_free(parsed);
        tess_key_free(sec);
    }

    printf("vectors: OK\n");
    return 0;
}
