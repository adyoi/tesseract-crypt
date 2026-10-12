/* test_sign.c — detached Ed25519ph signatures over buffers and files. */
#include "common.h"

int main(void) {
    tess_key *sec = NULL, *pub = NULL;
    tess_key *other = NULL, *other_pub = NULL;
    uint8_t sig[TESS_SIGNATURE_BYTES];
    uint8_t sig2[TESS_SIGNATURE_BYTES];
    const char *msg = "sign me if you can";
    uint8_t *copy;

    CHECK(sodium_init() >= 0);
    CHECK_ST(tess_keygen(&sec, &pub), TESS_OK);
    CHECK_ST(tess_keygen(&other, &other_pub), TESS_OK);

    /* buffer sign/verify */
    CHECK_ST(tess_sign((const uint8_t *)msg, strlen(msg), sec, sig), TESS_OK);
    CHECK_ST(tess_verify((const uint8_t *)msg, strlen(msg), pub, sig),
             TESS_OK);

    /* Ed25519ph is deterministic: signing twice gives the same bytes */
    CHECK_ST(tess_sign((const uint8_t *)msg, strlen(msg), sec, sig2),
             TESS_OK);
    CHECK(memcmp(sig, sig2, sizeof sig) == 0);

    /* wrong key fails */
    CHECK(tess_verify((const uint8_t *)msg, strlen(msg), other_pub, sig) !=
          TESS_OK);

    /* modified message fails */
    copy = (uint8_t *)test_strdup(msg);
    CHECK(copy != NULL);
    copy[0] = (uint8_t)(copy[0] ^ 1);
    CHECK(tess_verify(copy, strlen(msg), pub, sig) == TESS_ERR_SIGNATURE);
    free(copy);

    /* modified signature fails */
    sig2[0] ^= 1;
    CHECK(tess_verify((const uint8_t *)msg, strlen(msg), pub, sig2) ==
          TESS_ERR_SIGNATURE);
    sig2[0] ^= 1;

    /* empty message */
    CHECK_ST(tess_sign(NULL, 0, sec, sig), TESS_OK);
    CHECK_ST(tess_verify(NULL, 0, pub, sig), TESS_OK);

    /* file sign/verify */
    {
        uint8_t *data = fill_pattern(150000, 4);
        FILE *f = fopen("tess_sign_input.bin", "wb");
        CHECK(f != NULL);
        fwrite(data, 1, 150000, f);
        fclose(f);

        CHECK_ST(tess_sign_file("tess_sign_input.bin", sec, sig), TESS_OK);
        CHECK_ST(tess_verify_file("tess_sign_input.bin", pub, sig), TESS_OK);
        CHECK(tess_verify_file("tess_sign_input.bin", other_pub, sig) !=
              TESS_OK);

        /* tamper with the file: verification must fail */
        f = fopen("tess_sign_input.bin", "r+b");
        CHECK(f != NULL);
        fseek(f, 10, SEEK_SET);
        {
            int c = fgetc(f);
            fseek(f, 10, SEEK_SET);
            fputc(c ^ 0x20, f);
        }
        fclose(f);
        CHECK(tess_verify_file("tess_sign_input.bin", pub, sig) ==
              TESS_ERR_SIGNATURE);

        remove("tess_sign_input.bin");
        free(data);
    }

    /* signing requires an unlocked secret key */
    CHECK(tess_sign((const uint8_t *)msg, strlen(msg), pub, sig) !=
          TESS_OK);

    tess_key_free(sec);
    tess_key_free(pub);
    tess_key_free(other);
    tess_key_free(other_pub);
    printf("sign: OK\n");
    return 0;
}
