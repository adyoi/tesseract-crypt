/* test_keys.c — keygen, serialize/parse, lock/unlock, fingerprints. */
#include "common.h"

int main(void) {
    tess_key *sec = NULL, *pub = NULL;
    tess_key *parsed = NULL;
    tess_key *derived = NULL;
    char fp1[TESS_FINGERPRINT_HEX + 1];
    char fp2[TESS_FINGERPRINT_HEX + 1];
    char *armored = NULL;

    CHECK(sodium_init() >= 0);

    /* --- basic keygen --- */
    CHECK_ST(tess_keygen(&sec, &pub), TESS_OK);
    CHECK(tess_key_is_secret(sec) == 1);
    CHECK(tess_key_is_locked(sec) == 0);
    CHECK(tess_key_is_secret(pub) == 0);

    /* --- roundtrip of the public part --- */
    CHECK_ST(tess_key_get_public(sec, &derived), TESS_OK);
    CHECK_ST(tess_key_fingerprint(sec, fp1), TESS_OK);
    CHECK_ST(tess_key_fingerprint(derived, fp2), TESS_OK);
    CHECK(strcmp(fp1, fp2) == 0);
    CHECK(strlen(fp1) == TESS_FINGERPRINT_HEX);
    tess_key_free(derived);
    derived = NULL;

    /* --- serialize / parse (private, unlocked) --- */
    CHECK_ST(tess_key_serialize(sec, &armored), TESS_OK);
    CHECK(strstr(armored, "BEGIN TESSERACT PRIVATE KEY") != NULL);
    CHECK_ST(tess_key_parse(armored, NULL, &parsed), TESS_OK);
    {
        char fp3[TESS_FINGERPRINT_HEX + 1];
        CHECK_ST(tess_key_fingerprint(parsed, fp3), TESS_OK);
        CHECK(strcmp(fp1, fp3) == 0);
    }
    /* the reparsed key must decrypt what the original encrypted */
    {
        tess_seal_options so;
        tess_open_options oo;
        uint8_t *ct = NULL;
        size_t ct_len = 0;
        uint8_t *pt = NULL;
        size_t pt_len = 0;
        const char *msg = "key roundtrip works";

        tess_seal_options_init(&so);
        so.recipient_public = pub;
        CHECK_ST(tess_seal((const uint8_t *)msg, strlen(msg), &so, &ct,
                           &ct_len),
                 TESS_OK);
        tess_open_options_init(&oo);
        oo.recipient_secret = parsed;
        CHECK_ST(tess_open(ct, ct_len, &oo, &pt, &pt_len), TESS_OK);
        CHECK(pt_len == strlen(msg) && memcmp(pt, msg, pt_len) == 0);
        free(pt);
        free(ct);
    }
    tess_key_free(parsed);
    parsed = NULL;
    free(armored);
    armored = NULL;

    /* --- public serialize / parse --- */
    CHECK_ST(tess_key_serialize(pub, &armored), TESS_OK);
    CHECK(strstr(armored, "BEGIN TESSERACT PUBLIC KEY") != NULL);
    CHECK_ST(tess_key_parse(armored, NULL, &parsed), TESS_OK);
    CHECK(tess_key_is_secret(parsed) == 0);
    tess_key_free(parsed);
    parsed = NULL;
    free(armored);
    armored = NULL;

    /* --- locked keys (small KDF limits for test speed) --- */
    CHECK_ST(tess_key_lock(sec, "hunter2", 2, 32ull * 1024ull * 1024ull),
             TESS_OK);
    CHECK(tess_key_is_locked(sec) == 1);
    CHECK(tess_key_is_secret(sec) == 1);
    CHECK_ST(tess_key_serialize(sec, &armored), TESS_OK);
    CHECK(strstr(armored, "LOCKED") != NULL);

    /* loading without a passphrase must fail */
    CHECK_ST(tess_key_parse(armored, NULL, &parsed), TESS_ERR_PASSPHRASE);
    CHECK(parsed == NULL);

    /* wrong passphrase must fail */
    CHECK_ST(tess_key_parse(armored, "wrong", &parsed),
             TESS_ERR_PASSPHRASE);
    CHECK(parsed == NULL);

    /* right passphrase must work */
    CHECK_ST(tess_key_parse(armored, "hunter2", &parsed), TESS_OK);
    CHECK(tess_key_is_secret(parsed) == 1);
    CHECK(tess_key_is_locked(parsed) == 0);
    {
        char fp4[TESS_FINGERPRINT_HEX + 1];
        CHECK_ST(tess_key_fingerprint(parsed, fp4), TESS_OK);
        CHECK(strcmp(fp1, fp4) == 0); /* same identity as before */
    }

    /* locked key must be usable for decryption only after unlock */
    {
        tess_seal_options so;
        tess_open_options oo;
        uint8_t *ct = NULL;
        size_t ct_len = 0;
        uint8_t *pt = NULL;
        size_t pt_len = 0;
        const char *msg = "locked key message";

        tess_seal_options_init(&so);
        so.recipient_public = pub;
        CHECK_ST(tess_seal((const uint8_t *)msg, strlen(msg), &so, &ct,
                           &ct_len),
                 TESS_OK);

        tess_open_options_init(&oo);
        oo.recipient_secret = parsed; /* unlocked copy */
        CHECK_ST(tess_open(ct, ct_len, &oo, &pt, &pt_len), TESS_OK);
        CHECK(pt_len == strlen(msg) && memcmp(pt, msg, pt_len) == 0);
        free(pt);
        free(ct);
    }

    /* lock again with a new passphrase, then unlock with it */
    CHECK_ST(tess_key_lock(parsed, "newpass", 2, 32ull * 1024ull * 1024ull),
             TESS_OK);
    CHECK(tess_key_is_locked(parsed) == 1);
    CHECK_ST(tess_key_unlock(parsed, "newpass"), TESS_OK);
    CHECK(tess_key_is_locked(parsed) == 0);

    tess_key_free(parsed);
    free(armored);
    armored = NULL;

    /* --- tess_keygen_locked: locked from birth --- */
    {
        tess_key *ls = NULL, *lp = NULL;
        char fpl[TESS_FINGERPRINT_HEX + 1];
        CHECK_ST(tess_keygen_locked("born-locked", 2, 32ull * 1024ull * 1024ull,
                                    &ls, &lp),
                 TESS_OK);
        CHECK(tess_key_is_locked(ls) == 1);
        CHECK(tess_key_is_secret(lp) == 0);
        CHECK_ST(tess_key_fingerprint(ls, fpl), TESS_OK);
        CHECK(strlen(fpl) == TESS_FINGERPRINT_HEX);
        CHECK_ST(tess_key_save(ls, "test_locked.key"), TESS_OK);
        CHECK_ST(tess_key_save(lp, "test_locked.pub"), TESS_OK);
        CHECK_ST(tess_key_load("test_locked.key", "born-locked", &parsed),
                 TESS_OK);
        CHECK_ST(tess_key_unlock(parsed, "born-locked"), TESS_OK); /* no-op */
        tess_key_free(parsed);
        parsed = NULL;
        remove("test_locked.key");
        remove("test_locked.pub");
        tess_key_free(ls);
        tess_key_free(lp);
    }

    tess_key_free(sec);
    tess_key_free(pub);
    printf("keys: OK\n");
    return 0;
}
