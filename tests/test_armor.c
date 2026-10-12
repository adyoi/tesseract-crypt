/* test_armor.c — PEM-like armor encode/decode roundtrip. */
#include "common.h"

int main(void) {
    uint8_t *data;
    size_t len = 1000;
    char *armored = NULL;
    uint8_t *back = NULL;
    size_t back_len = 0;
    char *again = NULL;

    CHECK(sodium_init() >= 0);
    data = fill_pattern(len, 5);

    CHECK_ST(tess_armor(data, len, "TESSERACT MESSAGE", &armored), TESS_OK);
    CHECK(armored != NULL);
    CHECK(strstr(armored, "-----BEGIN TESSERACT MESSAGE-----") != NULL);
    CHECK(strstr(armored, "-----END TESSERACT MESSAGE-----") != NULL);
    CHECK(tess_is_armored((const uint8_t *)armored, strlen(armored)) == 1);
    CHECK(tess_is_armored(data, len) == 0);

    CHECK_ST(tess_dearmor(armored, &back, &back_len), TESS_OK);
    CHECK(bytes_eq(data, len, back, back_len));

    /* re-armoring the decoded bytes must give identical text */
    CHECK_ST(tess_armor(back, back_len, "TESSERACT MESSAGE", &again), TESS_OK);
    CHECK(strcmp(armored, again) == 0);

    /* malformed base64 must be rejected */
    {
        char *bad = test_strdup(armored);
        uint8_t *junk = NULL;
        size_t junk_len = 0;
        char *b = strstr(bad, "-----BEGIN");
        char *nl = b ? strchr(b, '\n') : NULL;
        CHECK(nl != NULL);
        nl[1] = '!'; /* not in the base64 alphabet */
        CHECK(tess_dearmor(bad, &junk, &junk_len) != TESS_OK);
        free(junk);
        free(bad);
    }

    /* empty payload */
    {
        char *empty_arm = NULL;
        uint8_t *eback = NULL;
        size_t elen = 0;
        CHECK_ST(tess_armor(data, 0, "X", &empty_arm), TESS_OK);
        CHECK_ST(tess_dearmor(empty_arm, &eback, &elen), TESS_OK);
        CHECK(elen == 0);
        free(eback);
        free(empty_arm);
    }

    free(again);
    free(back);
    free(armored);
    free(data);
    printf("armor: OK\n");
    return 0;
}
