/*
 * tess_pe.c - PE containers: a large file sealed as a sequence of frames.
 *
 * A container starts with the ASCII marker "PE" so the decrypt side
 * recognises it without an extra flag.  See tesseract.h for the layout.
 *
 * SPDX-License-Identifier: MIT
 */
#include "tess_internal.h"

#include <limits.h>

#define PE_HEADER_BYTES 21u
#define PE_VERSION 1u
#define PE_FLAG_ARMOR 0x01u

static const char PE_MAGIC[4] = "tsc";

void tess_pe_options_init(tess_pe_options *o) {
    if (o == NULL) return;
    memset(o, 0, sizeof *o);
}

int tess_is_pe_file(const char *path) {
    FILE *f;
    char m[3];
    size_t n;

    if (path == NULL) return 0;
    f = fopen(path, "rb");
    if (f == NULL) return 0;
    n = fread(m, 1, 3, f);
    fclose(f);
    return n == 3 && m[0] == PE_MAGIC[0] && m[1] == PE_MAGIC[1] &&
           m[2] == PE_MAGIC[2]
               ? 1
               : 0;
}

/* ------------------------------------------------------------------ */
/* atomic part writer (same policy as tess_seal.c)                     */
/* ------------------------------------------------------------------ */

typedef struct pe_writer {
    FILE *f;
    char path[4096];
    int failed;
} pe_writer;

static tess_status pe_open(pe_writer *w, const char *final_path) {
    memset(w, 0, sizeof *w);
    if (snprintf(w->path, sizeof w->path, "%s.part", final_path) >=
        (int)sizeof w->path) {
        return TESS_ERR_INVALID_ARG;
    }
    w->f = fopen(w->path, "wb");
    if (w->f == NULL) return TESS_ERR_IO;
    return TESS_OK;
}

static tess_status pe_write(pe_writer *w, const uint8_t *p, size_t n) {
    if (w->failed) return TESS_ERR_IO;
    if (n == 0) return TESS_OK;
    if (fwrite(p, 1, n, w->f) != n) {
        w->failed = 1;
        return TESS_ERR_IO;
    }
    return TESS_OK;
}

static void pe_abort(pe_writer *w) {
    if (w->f != NULL) {
        fclose(w->f);
        w->f = NULL;
    }
    if (w->path[0] != '\0') remove(w->path);
}

static tess_status pe_commit(pe_writer *w, const char *final_path) {
    if (w->failed) {
        pe_abort(w);
        return TESS_ERR_IO;
    }
    if (fflush(w->f) != 0) {
        pe_abort(w);
        return TESS_ERR_IO;
    }
    fclose(w->f);
    w->f = NULL;
    if (tess_replace_file(w->path, final_path) != 0) {
        remove(w->path);
        return TESS_ERR_IO;
    }
    w->path[0] = '\0';
    return TESS_OK;
}

static tess_status pe_file_size(FILE *f, uint64_t *out) {
    long end;
    *out = 0;
    if (fseek(f, 0, SEEK_END) != 0) return TESS_ERR_IO;
    end = ftell(f);
    if (end < 0) return TESS_ERR_IO;
    if (fseek(f, 0, SEEK_SET) != 0) return TESS_ERR_IO;
    *out = (uint64_t)end;
    return TESS_OK;
}

/* ------------------------------------------------------------------ */
/* encrypt                                                             */
/* ------------------------------------------------------------------ */

tess_status tess_seal_file_pe(const char *in_path, const char *out_path,
                              tess_seal_file_options *opt,
                              const tess_pe_options *pe) {
    FILE *in = NULL;
    pe_writer w;
    int active = 0;
    uint64_t total = 0, chunk = 0, remaining = 0;
    uint8_t *plain = NULL, *ct = NULL;
    size_t ct_len = 0;
    uint8_t flags = 0;
    tess_seal_options so;
    tess_status st;

    if (in_path == NULL || out_path == NULL || opt == NULL) {
        return TESS_ERR_INVALID_ARG;
    }

    chunk = (pe != NULL && pe->chunk_bytes != 0) ? pe->chunk_bytes
                                                : TESS_PE_DEFAULT_CHUNK;
    if (chunk < TESS_PE_MIN_CHUNK) chunk = TESS_PE_MIN_CHUNK;
    if (chunk > TESS_PE_MAX_CHUNK) chunk = TESS_PE_MAX_CHUNK;
    flags = (pe != NULL && pe->armor) ? PE_FLAG_ARMOR : 0;

    if (chunk > (uint64_t)SIZE_MAX - 64) return TESS_ERR_INVALID_ARG;

    in = fopen(in_path, "rb");
    if (in == NULL) return TESS_ERR_IO;
    st = pe_file_size(in, &total);
    if (st != TESS_OK) goto done;

    plain = (uint8_t *)malloc((size_t)chunk);
    if (plain == NULL) {
        st = TESS_ERR_NOMEM;
        goto done;
    }

    tess_seal_options_init(&so);
    so.recipient_public = opt->recipient_public;
    so.recipients = opt->recipients;
    so.recipient_count = opt->recipient_count;
    so.sender_secret = opt->sender_secret;
    so.sign = opt->sign;
    so.passphrase = opt->passphrase;
    so.chunk_size = opt->chunk_size;

    st = pe_open(&w, out_path);
    if (st != TESS_OK) goto done;
    active = 1;

    {
        uint8_t hdr[PE_HEADER_BYTES];
        hdr[0] = (uint8_t)PE_MAGIC[0];
        hdr[1] = (uint8_t)PE_MAGIC[1];
        hdr[2] = (uint8_t)PE_MAGIC[2];
        hdr[3] = (uint8_t)PE_VERSION;
        hdr[4] = flags;
        tess_wr_u64(hdr + 5, total);
        tess_wr_u64(hdr + 13, chunk);
        st = pe_write(&w, hdr, sizeof hdr);
        if (st != TESS_OK) goto done;
    }

    remaining = total;
    while (remaining > 0) {
        const size_t want = (size_t)((remaining < chunk) ? remaining : chunk);
        const size_t got = fread(plain, 1, want, in);
        if (got != want) {
            st = TESS_ERR_IO;
            goto done;
        }

        ct = NULL;
        ct_len = 0;
        st = tess_seal(plain, got, &so, &ct, &ct_len);
        if (st != TESS_OK) goto done;

        if (flags & PE_FLAG_ARMOR) {
            char *txt = NULL;
            size_t tlen;
            uint8_t lenb[4];
            st = tess_armor(ct, ct_len, "TESSERACT MESSAGE", &txt);
            tess_free(ct);
            ct = NULL;
            if (st != TESS_OK) goto done;
            tlen = strlen(txt);
            tess_wr_u32(lenb, (uint32_t)tlen);
            st = pe_write(&w, lenb, 4);
            if (st == TESS_OK) st = pe_write(&w, (const uint8_t *)txt, tlen);
            tess_free(txt);
            if (st != TESS_OK) goto done;
        } else {
            uint8_t lenb[4];
            if (ct_len > 0xffffffffu) {
                st = TESS_ERR_INTERNAL;
                goto done;
            }
            tess_wr_u32(lenb, (uint32_t)ct_len);
            st = pe_write(&w, lenb, 4);
            if (st == TESS_OK) st = pe_write(&w, ct, ct_len);
            tess_free(ct);
            ct = NULL;
            if (st != TESS_OK) goto done;
        }
        remaining -= got;
    }

    st = pe_commit(&w, out_path);
    active = 0;

done:
    if (active) pe_abort(&w);
    if (in != NULL) fclose(in);
    free(plain);
    tess_free(ct);
    return st;
}

/* ------------------------------------------------------------------ */
/* decrypt                                                             */
/* ------------------------------------------------------------------ */

tess_status tess_open_file_pe(const char *in_path, const char *out_path,
                              const tess_open_file_options *opt) {
    FILE *in = NULL;
    pe_writer w;
    int active = 0;
    uint8_t hdr[PE_HEADER_BYTES];
    uint8_t lenb[4];
    uint64_t announced = 0, total = 0, left = 0, written = 0;
    uint8_t flags;
    int signed_any = 0;
    tess_open_options oo;
    tess_status st;

    if (in_path == NULL || out_path == NULL || opt == NULL) {
        return TESS_ERR_INVALID_ARG;
    }

    in = fopen(in_path, "rb");
    if (in == NULL) return TESS_ERR_IO;

    if (fread(hdr, 1, sizeof hdr, in) != sizeof hdr) {
        st = TESS_ERR_FORMAT;
        goto done;
    }
    if (hdr[0] != PE_MAGIC[0] || hdr[1] != PE_MAGIC[1] ||
        hdr[2] != PE_MAGIC[2]) {
        st = TESS_ERR_FORMAT;
        goto done;
    }
    if (hdr[3] != PE_VERSION) {
        st = TESS_ERR_UNSUPPORTED;
        goto done;
    }
    flags = hdr[4];
    if ((flags & (uint8_t)~PE_FLAG_ARMOR) != 0) {
        st = TESS_ERR_FORMAT;
        goto done;
    }
    announced = tess_rd_u64(hdr + 5);

    st = pe_file_size(in, &total);
    if (st != TESS_OK) goto done;
    if (fseek(in, (long)PE_HEADER_BYTES, SEEK_SET) != 0) {
        st = TESS_ERR_IO;
        goto done;
    }
    left = (total > PE_HEADER_BYTES) ? total - PE_HEADER_BYTES : 0;

    tess_open_options_init(&oo);
    oo.recipient_secret = opt->recipient_secret;
    oo.passphrase = opt->passphrase;
    oo.required_signer = opt->required_signer;

    st = pe_open(&w, out_path);
    if (st != TESS_OK) goto done;
    active = 1;

    for (;;) {
        size_t n = fread(lenb, 1, 4, in);
        uint32_t flen;
        uint8_t *frame = NULL, *raw = NULL, *pt = NULL;
        size_t raw_len = 0, pt_len = 0;
        int signed_this = 0;

        if (n == 0) break;
        if (n != 4) {
            st = TESS_ERR_FORMAT;
            goto done;
        }
        flen = tess_rd_u32(lenb);
        if (flen == 0 || (uint64_t)flen + 4 > left) {
            /* a frame cannot be longer than what is actually left */
            st = TESS_ERR_FORMAT;
            goto done;
        }
        left -= (uint64_t)flen + 4;

        frame = (uint8_t *)malloc(flen);
        if (frame == NULL) {
            st = TESS_ERR_NOMEM;
            goto done;
        }
        if (fread(frame, 1, flen, in) != flen) {
            free(frame);
            st = TESS_ERR_FORMAT;
            goto done;
        }

        if (flags & PE_FLAG_ARMOR) {
            char *txt = (char *)malloc((size_t)flen + 1);
            if (txt == NULL) {
                free(frame);
                st = TESS_ERR_NOMEM;
                goto done;
            }
            memcpy(txt, frame, flen);
            txt[flen] = '\0';
            free(frame);
            st = tess_dearmor(txt, &raw, &raw_len);
            free(txt);
            if (st != TESS_OK) goto done;
        } else {
            raw = frame;
            raw_len = flen;
        }

        oo.out_signed = &signed_this;
        st = tess_open(raw, raw_len, &oo, &pt, &pt_len);
        free(raw);
        if (st != TESS_OK) goto done;
        if (signed_this) signed_any = 1;

        st = pe_write(&w, pt, pt_len);
        written += pt_len;
        tess_free(pt);
        if (st != TESS_OK) goto done;
    }

    if (left != 0) {
        /* trailing bytes after the last frame */
        st = TESS_ERR_FORMAT;
        goto done;
    }
    if (announced != UINT64_MAX && written != announced) {
        /* the container does not hold what it promised */
        st = TESS_ERR_FORMAT;
        goto done;
    }

    st = pe_commit(&w, out_path);
    active = 0;
    if (st == TESS_OK && opt->out_signed != NULL) {
        *(int *)(uintptr_t)opt->out_signed = signed_any;
    }

done:
    if (active) pe_abort(&w);
    if (in != NULL) fclose(in);
    return st;
}
