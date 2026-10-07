/* tess_status.c — status codes, version strings. */
#include "tess_internal.h"

const char *tess_strerror(tess_status st) {
    switch (st) {
    case TESS_OK:
        return "success";
    case TESS_ERR_INVALID_ARG:
        return "invalid argument";
    case TESS_ERR_NOMEM:
        return "out of memory";
    case TESS_ERR_IO:
        return "I/O error";
    case TESS_ERR_FORMAT:
        return "malformed or truncated data";
    case TESS_ERR_CRYPTO:
        return "authentication failed (wrong key or corrupted data)";
    case TESS_ERR_PASSPHRASE:
        return "passphrase required or incorrect";
    case TESS_ERR_SIGNATURE:
        return "signature verification failed";
    case TESS_ERR_SIGNER:
        return "signer identity does not match the required signer";
    case TESS_ERR_UNSUPPORTED:
        return "unsupported algorithm or version";
    case TESS_ERR_INTERNAL:
        return "internal error";
    default:
        return "unknown error";
    }
}

const char *tess_version(void) { return TESS_VERSION_STRING; }
