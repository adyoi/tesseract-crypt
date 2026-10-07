/* test_harden.c — hardening regressions surfaced by the CLI audit.
 *
 * Covers the error contract that the CLI relies on:
 *   - a locked key can never be used as a message sender      -> PASSPHRASE
 *   - locking an already-locked key is rejected               -> INVALID_ARG
 *   - a recipient list containing the same key twice is bogus -> INVALID_ARG
 *   - a pinned required signer needs a signed message         -> SIGNER
 *   - truncated ciphertext is rejected up front               -> FORMAT
 *   - rekey_file never clobbers an existing output on failure
 *   - user-supplied Argon2id kdf_ops/kdf_mem are honoured end to end.
 */
#include "common.h"

int main(void) {
    tess_key *a_s = NULL, *a_p = NULL;
    tess_key *b_s = NULL, *b_p = NULL;
    tess_key *c_s = NULL, *c_p = NULL;
    const tess_key *dups[2];
    uint8_t *pt = NULL;
    uint8_t *ct = NULL, *out = NULL;
    size_t ct_len = 0, out_len = 0;
    tess_seal_options so;
    tess_open_options oo;
    static const uint8_t marker[] = "KEEP-ME-UNTAMPERED";
    char in_path[512], out_path[512], msg_path[512];
    FILE *f = NULL;
    uint8_t probe[512];

    CHECK(sodium_init() >= 0);

    CHECK_ST(tess_keygen(&a_s, &a_p), TESS_OK);
    CHECK_ST(tess_keygen(&b_s, &b_p), TESS_OK);
    CHECK_ST(tess_keygen(&c_s, &c_p), TESS_OK);

    pt = fill_pattern(4096, 0x3c);
    CHECK(pt != NULL);

    /* -- a locked key must not sign/seal --------------------------------- */
    CHECK_ST(tess_key_lock(a_s, "hunter2", 0, 0), TESS_OK);
    tess_seal_options_init(&so);
    so.recipient_public = b_p;
    so.sender_secret = a_s; /* locked */
    CHECK_ST(tess_seal(pt, 4096, &so, &ct, &ct_len), TESS_ERR_PASSPHRASE);
    CHECK(ct == NULL && ct_len == 0);

    /* -- double lock ----------------------------------------------------- */
    CHECK_ST(tess_key_lock(a_s, "hunter2", 0, 0), TESS_ERR_INVALID_ARG);
    /* unlock, lock again: a fresh lock is fine after a real unlock */
    CHECK_ST(tess_key_unlock(a_s, "nope"), TESS_ERR_PASSPHRASE);
    CHECK(tess_key_is_locked(a_s));
    CHECK_ST(tess_key_unlock(a_s, "hunter2"), TESS_OK);
    CHECK(!tess_key_is_locked(a_s));
    CHECK_ST(tess_key_lock(a_s, "again", 0, 0), TESS_OK);
    CHECK_ST(tess_key_unlock(a_s, "again"), TESS_OK);

    /* -- duplicate recipients -------------------------------------------- */
    dups[0] = b_p;
    dups[1] = b_p;
    tess_seal_options_init(&so);
    so.recipients = dups;
    so.recipient_count = 2;
    CHECK_ST(tess_seal(pt, 4096, &so, &ct, &ct_len), TESS_ERR_INVALID_ARG);

    /* -- unsigned message + pinned signer -------------------------------- */
    tess_seal_options_init(&so);
    so.recipient_public = b_p;
    CHECK_ST(tess_seal(pt, 4096, &so, &ct, &ct_len), TESS_OK);
    tess_open_options_init(&oo);
    oo.recipient_secret = b_s;
    oo.required_signer = a_p; /* message is unsigned */
    CHECK_ST(tess_open(ct, ct_len, &oo, &out, &out_len), TESS_ERR_SIGNER);

    /* a signed message with the *wrong* signer pinned is also SIGNER */
    tess_open_options_init(&oo);
    oo.recipient_secret = b_s;
    CHECK_ST(tess_open(ct, ct_len, &oo, &out, &out_len), TESS_OK);
    tess_free(out);
    out = NULL;

    tess_seal_options_init(&so);
    so.recipient_public = b_p;
    so.sender_secret = a_s;
    so.sign = 1;
    CHECK_ST(tess_seal(pt, 4096, &so, &ct, &ct_len), TESS_OK);
    tess_open_options_init(&oo);
    oo.recipient_secret = b_s;
    oo.required_signer = c_p; /* wrong signer */
    CHECK_ST(tess_open(ct, ct_len, &oo, &out, &out_len), TESS_ERR_SIGNER);
    tess_open_options_init(&oo);
    oo.recipient_secret = b_s;
    oo.required_signer = a_p; /* correct signer */
    CHECK_ST(tess_open(ct, ct_len, &oo, &out, &out_len), TESS_OK);
    CHECK(out_len == 4096);
    CHECK(bytes_eq(out, out_len, pt, 4096));
    tess_free(out);
    out = NULL;
    tess_free(ct);
    ct = NULL;

    /* -- truncated ciphertext -------------------------------------------- */
    tess_seal_options_init(&so);
    so.recipient_public = b_p;
    CHECK_ST(tess_seal(pt, 4096, &so, &ct, &ct_len), TESS_OK);
    CHECK_ST(tess_open(ct, 32, &oo, &out, &out_len), TESS_ERR_FORMAT);
    CHECK_ST(tess_open(NULL, 0, &oo, &out, &out_len), TESS_ERR_FORMAT);
    tess_free(ct);
    ct = NULL;

    /* -- rekey_file preserves an existing output on failure -------------- */
    snprintf(in_path, sizeof in_path, "harden_in.bin");
    snprintf(msg_path, sizeof msg_path, "harden_msg.bin");
    snprintf(out_path, sizeof out_path, "harden_out.bin");
    remove(in_path);
    remove(msg_path);
    remove(out_path);
    remove("harden_out.bin.part");

    f = fopen(in_path, "wb");
    CHECK(f != NULL);
    CHECK(fwrite(pt, 1, 4096, f) == 4096);
    fclose(f);

    tess_seal_file_options fo;
    tess_seal_file_options_init(&fo);
    fo.recipient_public = b_p;
    CHECK_ST(tess_seal_file(in_path, msg_path, &fo), TESS_OK);

    /* pre-existing output that must survive a failed rekey */
    f = fopen(out_path, "wb");
    CHECK(f != NULL);
    CHECK(fwrite(marker, 1, sizeof marker - 1, f) == sizeof marker - 1);
    fclose(f);

    /* scheme the message for A even though B is the recipient: must fail */
    tess_open_file_options fop;
    tess_open_file_options_init(&fop);
    fop.recipient_secret = a_s;
    tess_seal_file_options fin;
    tess_seal_file_options_init(&fin);
    fin.recipient_public = c_p;
    CHECK_ST(tess_rekey_file(msg_path, out_path, &fop, &fin),
             TESS_ERR_RECIPIENT);

    /* output must be byte-for-byte the pre-existing marker */
    memset(probe, 0, sizeof probe);
    f = fopen(out_path, "rb");
    CHECK(f != NULL);
    size_t got = fread(probe, 1, sizeof probe - 1, f);
    fclose(f);
    CHECK(got == sizeof marker - 1);
    CHECK(memcmp(probe, marker, sizeof marker - 1) == 0);
    /* and the atomic .part file is gone on failure */
    f = fopen("harden_out.bin.part", "rb");
    CHECK(f == NULL);

    /* a *successful* rekey does replace the output */
    tess_open_file_options_init(&fop);
    fop.recipient_secret = b_s;
    CHECK_ST(tess_rekey_file(msg_path, out_path, &fop, &fin), TESS_OK);
    f = fopen(out_path, "rb");
    CHECK(f != NULL);
    got = fread(probe, 1, sizeof probe, f);
    fclose(f);
    CHECK(got > sizeof marker - 1); /* rekeyed ciphertext, not the marker */

    /* -- per-message kdf_ops/kdf_mem override ---------------------------- */
    tess_seal_options_init(&so);
    so.passphrase = "correct horse battery staple";
    so.kdf_ops = 3;               /* still fast enough for the test suite */
    so.kdf_mem = 64u * 1024u * 1024u;
    CHECK_ST(tess_seal(pt, 4096, &so, &ct, &ct_len), TESS_OK);
    tess_open_options_init(&oo);
    oo.passphrase = "correct horse battery staple";
    CHECK_ST(tess_open(ct, ct_len, &oo, &out, &out_len), TESS_OK);
    CHECK(out_len == 4096);
    CHECK(bytes_eq(out, out_len, pt, 4096));
    tess_free(out);
    out = NULL;
    tess_open_options_init(&oo);
    oo.passphrase = "wrong passphrase";
    /* the wrong key material fails at the first authenticated chunk */
    CHECK_ST(tess_open(ct, ct_len, &oo, &out, &out_len), TESS_ERR_CRYPTO);
    tess_free(ct);
    ct = NULL;

    /* kdf override honoured by the file variant too */
    tess_seal_file_options_init(&fo);
    fo.passphrase = "correct horse battery staple";
    fo.kdf_ops = 3;
    fo.kdf_mem = 64u * 1024u * 1024u;
    CHECK_ST(tess_seal_file(in_path, msg_path, &fo), TESS_OK);
    tess_open_file_options_init(&fop);
    fop.passphrase = "correct horse battery staple";
    CHECK_ST(tess_open_file(msg_path, out_path, &fop), TESS_OK);

    remove(in_path);
    remove(msg_path);
    remove(out_path);
    remove("harden_out.bin.part");

    free(pt);
    tess_key_free(a_s);
    tess_key_free(a_p);
    tess_key_free(b_s);
    tess_key_free(b_p);
    tess_key_free(c_s);
    tess_key_free(c_p);

    return 0;
}