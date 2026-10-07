/*
 * tesseract.hpp — header-only C++17 wrapper for libtesseract_crypt.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef TESSERACT_HPP
#define TESSERACT_HPP

#include "tesseract.h"

#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tess {

/** Exception carrying a tess_status code. */
class error : public std::runtime_error {
public:
    explicit error(tess_status st)
        : std::runtime_error(tess_strerror(st)), st_(st) {}
    tess_status status() const noexcept { return st_; }

private:
    tess_status st_;
};

inline void check(tess_status st) {
    if (st != TESS_OK) throw error(st);
}

using bytes = std::vector<uint8_t>;

namespace detail {
struct key_deleter {
    void operator()(tess_key *k) const noexcept { tess_key_free(k); }
};
} // namespace detail

/** RAII wrapper around tess_key (move-only). */
class key {
public:
    key() = default;
    explicit key(tess_key *raw) : k_(raw) {}

    static key generate() {
        tess_key *sec = nullptr, *pub = nullptr;
        check(tess_keygen(&sec, &pub));
        tess_key_free(pub);
        return key(sec);
    }

    static key generate_locked(const std::string &passphrase,
                               uint32_t ops = 0, uint64_t mem = 0) {
        tess_key *sec = nullptr, *pub = nullptr;
        check(tess_keygen_locked(passphrase.c_str(), ops, mem, &sec, &pub));
        tess_key_free(pub);
        return key(sec);
    }

    static key load(const std::string &path,
                    const std::string &passphrase = {}) {
        tess_key *k = nullptr;
        check(tess_key_load(path.c_str(),
                            passphrase.empty() ? nullptr : passphrase.c_str(),
                            &k));
        return key(k);
    }

    static key parse(const std::string &armored,
                     const std::string &passphrase = {}) {
        tess_key *k = nullptr;
        check(tess_key_parse(armored.c_str(),
                             passphrase.empty() ? nullptr : passphrase.c_str(),
                             &k));
        return key(k);
    }

    key public_part() const {
        tess_key *p = nullptr;
        check(tess_key_get_public(get(), &p));
        return key(p);
    }

    void save(const std::string &path) const { check(tess_key_save(get(), path.c_str())); }

    std::string serialize() const {
        char *s = nullptr;
        check(tess_key_serialize(get(), &s));
        std::string out(s);
        tess_free(s);
        return out;
    }

    std::string fingerprint() const {
        char hex[TESS_FINGERPRINT_HEX + 1] = {};
        check(tess_key_fingerprint(get(), hex));
        return std::string(hex);
    }

    void unlock(const std::string &passphrase) {
        check(tess_key_unlock(get(), passphrase.c_str()));
    }

    void lock(const std::string &passphrase, uint32_t ops = 0,
              uint64_t mem = 0) {
        check(tess_key_lock(get(), passphrase.c_str(), ops, mem));
    }

    bool is_secret() const { return tess_key_is_secret(get()) != 0; }
    bool is_locked() const { return tess_key_is_locked(get()) != 0; }

    tess_key *get() const noexcept { return k_.get(); }
    explicit operator bool() const noexcept { return k_ != nullptr; }

private:
    std::unique_ptr<tess_key, detail::key_deleter> k_;
};

/* ------------------------------------------------------------------ */
/* seal / open                                                         */
/* ------------------------------------------------------------------ */

/**
 * Encrypt `data`.
 * @param recipient public key of the receiver (nullptr => passphrase mode)
 * @param sender    private key of the sender (enables identity binding)
 * @param sign      attach an Ed25519 signature (requires sender)
 * @param chunk_size 0 => default (64 KiB)
 */
inline bytes seal(std::string_view data, const key *recipient = nullptr,
                  const key *sender = nullptr, bool sign = false,
                  const std::string &passphrase = {},
                  uint32_t chunk_size = 0) {
    tess_seal_options o;
    tess_seal_options_init(&o);
    o.recipient_public = recipient ? recipient->get() : nullptr;
    o.sender_secret = sender ? sender->get() : nullptr;
    o.sign = sign ? 1 : 0;
    o.passphrase = passphrase.empty() ? nullptr : passphrase.c_str();
    o.chunk_size = chunk_size;

    uint8_t *out = nullptr;
    size_t out_len = 0;
    check(tess_seal(reinterpret_cast<const uint8_t *>(data.data()),
                    data.size(), &o, &out, &out_len));
    bytes result(out, out + out_len);
    tess_free(out);
    return result;
}

/**
 * Decrypt a message produced by seal().
 * @param passphrase     used in passphrase mode
 * @param required_signer pin to this sender identity (optional)
 * @param signed_out     receives 1 if the message was signed (optional)
 */
inline bytes open(const bytes &message, const key *recipient = nullptr,
                  const std::string &passphrase = {},
                  const key *required_signer = nullptr,
                  int *signed_out = nullptr) {
    tess_open_options o;
    tess_open_options_init(&o);
    o.recipient_secret = recipient ? recipient->get() : nullptr;
    o.passphrase = passphrase.empty() ? nullptr : passphrase.c_str();
    o.required_signer = required_signer ? required_signer->get() : nullptr;
    o.out_signed = signed_out;

    uint8_t *out = nullptr;
    size_t out_len = 0;
    check(tess_open(message.data(), message.size(), &o, &out, &out_len));
    bytes result(out, out + out_len);
    tess_free(out);
    return result;
}

inline std::string open_string(const bytes &message,
                               const key *recipient = nullptr,
                               const std::string &passphrase = {},
                               const key *required_signer = nullptr,
                               int *signed_out = nullptr) {
    bytes pt = open(message, recipient, passphrase, required_signer, signed_out);
    return std::string(pt.begin(), pt.end());
}

/* ------------------------------------------------------------------ */
/* armor / inspect                                                     */
/* ------------------------------------------------------------------ */

inline std::string armor(const bytes &data,
                         const std::string &label = "TESSERACT MESSAGE") {
    char *s = nullptr;
    check(tess_armor(data.data(), data.size(), label.c_str(), &s));
    std::string out(s);
    tess_free(s);
    return out;
}

inline bytes dearmor(const std::string &text) {
    uint8_t *raw = nullptr;
    size_t len = 0;
    check(tess_dearmor(text.c_str(), &raw, &len));
    bytes out(raw, raw + len);
    tess_free(raw);
    return out;
}

inline bool is_armored(const std::string &text) {
    return tess_is_armored(reinterpret_cast<const uint8_t *>(text.data()),
                           text.size()) != 0;
}

inline tess_message_info inspect(const bytes &message) {
    tess_message_info info;
    check(tess_inspect(message.data(), message.size(), &info));
    return info;
}

/* ------------------------------------------------------------------ */
/* sign / verify                                                       */
/* ------------------------------------------------------------------ */

inline bytes sign(std::string_view msg, const key &secret) {
    uint8_t sig[TESS_SIGNATURE_BYTES];
    check(tess_sign(reinterpret_cast<const uint8_t *>(msg.data()), msg.size(),
                    secret.get(), sig));
    return bytes(sig, sig + sizeof sig);
}

inline bool verify(std::string_view msg, const key &public_key,
                   const bytes &signature) {
    if (signature.size() != TESS_SIGNATURE_BYTES) return false;
    return tess_verify(reinterpret_cast<const uint8_t *>(msg.data()), msg.size(),
                       public_key.get(), signature.data()) == TESS_OK;
}

} // namespace tess

#endif /* TESSERACT_HPP */
