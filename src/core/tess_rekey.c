/*
 * tess_rekey.c — re-encrypt existing ciphertext to new recipients.
 */
#include "tess_internal.h"

#include <sodium.h>
#include <sodium/utils.h>
#include <string.h>

tess_status tess_rekey(const uint8_t *ct, size_t ct_len,
                       const tess_open_options *open_opt,
                       const tess_seal_options *rekey_opt,
                       uint8_t **out, size_t *out_len) {
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    tess_status st;

    if (ct == NULL || ct_len == 0 || open_opt == NULL || rekey_opt == NULL ||
        out == NULL || out_len == NULL) {
        return TESS_ERR_INVALID_ARG;
    }

    /* Decrypt to plaintext; this preserves signature verification semantics
     * because tess_open checks signature if present and follows options. */
    st = tess_open(ct, ct_len, open_opt, &pt, &pt_len);
    if (st != TESS_OK) {
        return st;
    }

    /* Reseal with new options. We do not attempt to preserve sender/signature
     * from the original unless rekey_opt specifies them; if the original was
     * signed and the caller wants to preserve signing identity, they must set
     * sender_secret in rekey_opt. */
    st = tess_seal(pt, pt_len, rekey_opt, out, out_len);

    /* Zero plaintext before returning. */
    if (pt != NULL) {
        sodium_memzero(pt, pt_len);
        tess_free(pt);
    }
    return st;
}

tess_status tess_rekey_buf(const uint8_t *ct, size_t ct_len,
                           const tess_open_options *open_opt,
                           const tess_seal_options *rekey_opt,
                           uint8_t **out, size_t *out_len) {
    return tess_rekey(ct, ct_len, open_opt, rekey_opt, out, out_len);
}
