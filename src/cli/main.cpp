/*
 * main.cpp — tesseract-crypt (CLI, alias: tscrypt); command line interface
 * for libtesseract_crypt.
 *
 * Subcommands: keygen, pubkey, encrypt, decrypt, sign, verify, inspect,
 *              info, version, help.
 *
 * SPDX-License-Identifier: MIT
 */
#include "tesseract/tesseract.hpp"

#include <sodium.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <io.h>
#define TESS_ISATTY(fd) _isatty(fd)
#define TESS_FILENO(f) _fileno(f)
#include <conio.h>
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#define TESS_ISATTY(fd) isatty(fd)
#define TESS_FILENO(f) fileno(f)
#endif

namespace {

/* ------------------------------------------------------------------ */
/* exit codes                                                          */
/* ------------------------------------------------------------------ */
constexpr int EXIT_OK = 0;
constexpr int EXIT_FAIL = 1;
constexpr int EXIT_USAGE = 2;
constexpr int EXIT_AUTH = 3; /* authentication / signature failure */

int exit_for(tess_status st) {
    switch (st) {
    case TESS_OK:
        return EXIT_OK;
    case TESS_ERR_INVALID_ARG:
        return EXIT_USAGE;
    case TESS_ERR_CRYPTO:
    case TESS_ERR_SIGNATURE:
    case TESS_ERR_SIGNER:
    case TESS_ERR_PASSPHRASE:
    case TESS_ERR_RECIPIENT:
        return EXIT_AUTH;
    default:
        return EXIT_FAIL;
    }
}

void fail(tess_status st, const std::string &what) {
    std::cerr << "tesseract-crypt: " << what << ": " << tess_strerror(st) << "\n";
}

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

bool stdout_tty() { return TESS_ISATTY(TESS_FILENO(stdout)) != 0; }

std::string getpass(const char *prompt) {
    std::string s;
    std::fputs(prompt, stderr);
    std::fflush(stderr);
#ifdef _WIN32
    if (_isatty(_fileno(stdin)) == 0) {
        /* piped input: read one line from stdin */
        std::getline(std::cin, s);
        std::fputs("\n", stderr);
        return s;
    }
    for (;;) {
        int c = _getch();
        if (c == 13 || c == 10) break;
        if (c == 8 || c == 127) {
            if (!s.empty()) s.pop_back();
            continue;
        }
        if (c == 0 || c == 0xe0) {
            _getch(); /* swallow extended key */
            continue;
        }
        if (c == 3) std::exit(130);
        s.push_back(static_cast<char>(c));
    }
    std::fputs("\n", stderr);
#else
    termios oldt{}, newt{};
    if (tcgetattr(STDIN_FILENO, &oldt) == 0) {
        newt = oldt;
        newt.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        std::getline(std::cin, s);
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    } else {
        std::getline(std::cin, s);
    }
    std::fputs("\n", stderr);
#endif
    return s;
}

bool read_stream(std::istream &in, std::string &out) {
    char buf[65536];
    for (;;) {
        in.read(buf, sizeof buf);
        std::streamsize n = in.gcount();
        if (n > 0) out.append(buf, static_cast<size_t>(n));
        if (!in) break;
    }
    /* a short/full read at EOF sets failbit too: that is success, not error */
    return in.eof() || !in.bad();
}

/* read input: "-" or empty => stdin, otherwise a file path */
bool read_input(const std::string &path, std::string &data) {
    if (path.empty() || path == "-") {
        std::cin.sync();
        return read_stream(std::cin, data);
    }
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "tesseract-crypt: cannot open " << path << "\n";
        return false;
    }
    return read_stream(f, data);
}

bool write_output(const std::string &path, const std::string &data) {
    if (path.empty() || path == "-") {
        std::cout.write(data.data(),
                        static_cast<std::streamsize>(data.size()));
        std::cout.flush();
        return static_cast<bool>(std::cout);
    }
    std::string part = path + ".part";
    {
        std::ofstream f(part, std::ios::binary | std::ios::trunc);
        if (!f) {
            std::cerr << "tesseract-crypt: cannot write " << part << "\n";
            return false;
        }
        f.write(data.data(), static_cast<std::streamsize>(data.size()));
        f.flush();
        if (!f) {
            f.close();
            std::remove(part.c_str());
            std::cerr << "tesseract-crypt: write error on " << part << "\n";
            return false;
        }
    }
    if (
#ifdef _WIN32
        MoveFileExA(part.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING) ==
            0
#else
        std::rename(part.c_str(), path.c_str()) != 0
#endif
    ) {
        std::remove(part.c_str());
        std::cerr << "tesseract-crypt: cannot rename " << part << " -> " << path
                  << "\n";
        return false;
    }
    return true;
}

void remove_part(const std::string &path) {
    if (!path.empty() && path != "-") {
        std::string part = path + ".part";
        std::remove(part.c_str());
    }
}

/* ------------------------------------------------------------------ */
/* PE containers: large files as a sequence of sealed chunks           */
/* ------------------------------------------------------------------ */
/*
 * A PE container starts with the ASCII marker "PE" so the decrypt side
 * recognises a split file without any extra flag: the first two bytes of
 * the file decide.  Layout (integers are little endian):
 *
 *    0   2  magic "PE"
 *    2   1  version (1)
 *    3   1  flags (bit 0: the frames are armored)
 *    4   8  size of the original plaintext
 *   12   8  chunk size that was used
 *   20  ..  repeated: 4 byte length, then that many bytes of ciphertext
 */

/** The files of a directory, sorted; with `recursive` also the subtrees. */
std::vector<std::string> pe_list_dir(const std::string &dir, bool recursive) {
    std::vector<std::string> out;
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) return out;
    const auto opts = std::filesystem::directory_options::skip_permission_denied;
    if (recursive) {
        for (auto const &entry : std::filesystem::recursive_directory_iterator(dir, opts, ec)) {
            if (ec) break;
            std::error_code fec;
            if (entry.is_regular_file(fec)) out.push_back(entry.path().string());
        }
    } else {
        for (auto const &entry : std::filesystem::directory_iterator(dir, opts, ec)) {
            if (ec) break;
            std::error_code fec;
            if (entry.is_regular_file(fec)) out.push_back(entry.path().string());
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}

/* ------------------------------------------------------------------ */
/* argument parsing helpers                                            */
/* ------------------------------------------------------------------ */

/* very small parser: collects flags and their values */
struct parser {
    std::vector<std::string> v;
    size_t i = 1;
    std::string cmd;

    parser(int argc, char **argv) {
        for (int k = 0; k < argc; k++) v.emplace_back(argv[k]);
        if (argc > 1) cmd = v[1];
    }

    bool has(const std::string &flag) const {
        for (size_t k = 1; k < v.size(); k++) {
            if (v[k] == flag) return true;
        }
        return false;
    }

    /* returns value for flag, or def when absent */
    std::string get(const std::string &flag, const std::string &def = {}) const {
        for (size_t k = 1; k + 1 < v.size(); k++) {
            if (v[k] == flag) return v[k + 1];
        }
        return def;
    }

    /* every value following repeated occurrences of flag (order kept) */
    std::vector<std::string> get_all(const std::string &flag) const {
        std::vector<std::string> out;
        for (size_t k = 1; k + 1 < v.size(); k++) {
            if (v[k] == flag) out.push_back(v[k + 1]);
        }
        return out;
    }

    bool get_u32(const std::string &flag, uint32_t &out) const {
        std::string s = get(flag);
        if (s.empty()) return false;
        char *end = nullptr;
        unsigned long long n = std::strtoull(s.c_str(), &end, 10);
        if (end == nullptr || *end != '\0' || n == 0 || n > 0xffffffffull) {
            return false;
        }
        out = static_cast<uint32_t>(n);
        return true;
    }

    bool get_u64(const std::string &flag, uint64_t &out) const {
        std::string s = get(flag);
        if (s.empty()) return false;
        char *end = nullptr;
        unsigned long long n = std::strtoull(s.c_str(), &end, 10);
        if (end == nullptr || *end != '\0' || n == 0) return false;
        out = n;
        return true;
    }

    bool get_u64_mb(const std::string &flag, uint64_t &out_mb) const {
        std::string s = get(flag);
        if (s.empty()) return false;
        char *end = nullptr;
        unsigned long long n = std::strtoull(s.c_str(), &end, 10);
        if (end == nullptr || *end != '\0' || n == 0) return false;
        /* the value is converted to bytes by the caller: refuse anything
         * that would overflow the multiplication */
        if (n > (0xffffffffull / (1024ull * 1024ull))) return false;
        out_mb = n;
        return true;
    }
};

/* ------------------------------------------------------------------ */
/* PE containers: thin wrappers over the library                      */
/* ------------------------------------------------------------------ */

/** 1 when the file starts with the "PE" marker. */
bool pe_is_container(const std::string &path) {
    return tess_is_pe_file(path.c_str()) != 0;
}

/** Seal `in_path` as a PE container of chunk_mb MiB frames. */
bool pe_encrypt_file(const std::string &in_path, const std::string &out_path,
                     const tess_seal_options &so, bool armor,
                     uint64_t chunk_mb) {
    tess_seal_file_options fo;
    tess_seal_file_options_init(&fo);
    fo.recipient_public = so.recipient_public;
    fo.recipients = so.recipients;
    fo.recipient_count = so.recipient_count;
    fo.sender_secret = so.sender_secret;
    fo.sign = so.sign;
    fo.passphrase = so.passphrase;
    fo.chunk_size = so.chunk_size;

    tess_pe_options pe;
    tess_pe_options_init(&pe);
    pe.chunk_bytes = chunk_mb * 1024ull * 1024ull;
    pe.armor = armor ? 1 : 0;

    return tess_seal_file_pe(in_path.c_str(), out_path.c_str(), &fo, &pe) ==
           TESS_OK;
}

/** Unpack a PE container back into one plain file. */
bool pe_decrypt_file(const std::string &in_path, const std::string &out_path,
                     const tess_open_options &oo) {
    tess_open_file_options fo;
    tess_open_file_options_init(&fo);
    fo.recipient_secret = oo.recipient_secret;
    fo.passphrase = oo.passphrase;
    fo.required_signer = oo.required_signer;

    return tess_open_file_pe(in_path.c_str(), out_path.c_str(), &fo) == TESS_OK;
}

/* ------------------------------------------------------------------ */
/* batch encrypt: every file of a directory                           */
/* ------------------------------------------------------------------ */

int cmd_encrypt_batch(const parser &p, const tess_seal_options &so_base,
                      bool use_passphrase, const std::string &passphrase) {
    const std::string dir = p.get("--dir");
    const bool recursive = p.has("--recursive");
    const bool armor = p.has("--armor");
    const bool force_pe = p.has("--pe");

    std::string out_dir = p.get("--out-dir");
    if (out_dir.empty()) out_dir = p.get("-o");
    if (out_dir.empty() || out_dir == "-") out_dir = dir;

    const std::vector<std::string> files = pe_list_dir(dir, recursive);
    if (files.empty()) {
        std::cerr << "tesseract-crypt encrypt: no files found in " << dir << "\n";
        return EXIT_FAIL;
    }

    std::error_code ec;
    std::filesystem::create_directories(out_dir, ec);

    uint64_t pe_mb = 256;
    if (!p.get_u64("--pe-chunk-size", pe_mb) && p.has("--pe-chunk-size")) {
        std::cerr << "tesseract-crypt encrypt: invalid --pe-chunk-size\n";
        return EXIT_USAGE;
    }
    if (p.has("--pe-chunk-size")) pe_mb = std::min<uint64_t>(pe_mb, 1024ull);

    int rc = EXIT_OK;
    for (const std::string &in_path : files) {
        /* keep the tree of the input directory in the output directory */
        std::filesystem::path rel = std::filesystem::relative(in_path, dir, ec);
        std::filesystem::path out_path = std::filesystem::path(out_dir) / rel;
        out_path += ".enc";
        if (recursive) {
            std::filesystem::create_directories(out_path.parent_path(), ec);
        }

        const uint64_t size = std::filesystem::file_size(in_path, ec);
        if (ec) {
            std::cerr << "tesseract-crypt encrypt: cannot stat " << in_path << "\n";
            rc = EXIT_FAIL;
            continue;
        }

        tess_seal_options so = so_base;
        so.passphrase = use_passphrase ? passphrase.c_str() : nullptr;

        /* Files above the practical limit go into a PE container; --pe
         * forces the container for every file. */
        const bool want_pe = force_pe || size > (512ull * 1024ull * 1024ull);
        if (want_pe) {
            if (pe_encrypt_file(in_path, out_path.string(), so, armor, pe_mb)) {
                std::cerr << "encrypted (pe): " << in_path << " -> " << out_path.string() << "\n";
            } else {
                std::cerr << "tesseract-crypt encrypt: failed on " << in_path << "\n";
                rc = EXIT_FAIL;
            }
            continue;
        }

        tess_seal_file_options fo;
        tess_seal_file_options_init(&fo);
        fo.recipient_public = so.recipient_public;
        fo.recipients = so.recipients;
        fo.recipient_count = so.recipient_count;
        fo.sender_secret = so.sender_secret;
        fo.sign = so.sign;
        fo.passphrase = so.passphrase;
        fo.chunk_size = so.chunk_size;
        if (tess_seal_file(in_path.c_str(), out_path.string().c_str(), &fo) == TESS_OK) {
            std::cerr << "encrypted: " << in_path << " -> " << out_path.string() << "\n";
        } else {
            std::cerr << "tesseract-crypt encrypt: failed on " << in_path << "\n";
            rc = EXIT_FAIL;
        }
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* batch decrypt: every file of a directory                           */
/* ------------------------------------------------------------------ */

int cmd_decrypt_batch(const parser &p, const tess_open_options &oo_base,
                      const std::string &passphrase, bool use_passphrase) {
    const std::string dir = p.get("--dir");
    const bool recursive = p.has("--recursive");

    std::string out_dir = p.get("--out-dir");
    if (out_dir.empty()) out_dir = p.get("-o");
    if (out_dir.empty() || out_dir == "-") out_dir = dir;

    const std::vector<std::string> files = pe_list_dir(dir, recursive);
    if (files.empty()) {
        std::cerr << "tesseract-crypt decrypt: no files found in " << dir << "\n";
        return EXIT_FAIL;
    }

    std::error_code ec;
    std::filesystem::create_directories(out_dir, ec);

    int rc = EXIT_OK;
    for (const std::string &in_path : files) {
        std::filesystem::path rel = std::filesystem::relative(in_path, dir, ec);
        std::filesystem::path out_path = std::filesystem::path(out_dir) / rel;
        if (rel.extension() == ".enc") {
            out_path.replace_extension();
        } else {
            out_path += ".dec";
        }
        if (recursive) {
            std::filesystem::create_directories(out_path.parent_path(), ec);
        }

        tess_open_options oo = oo_base;
        oo.passphrase = use_passphrase ? passphrase.c_str() : nullptr;

        /* A PE container announces itself with the "PE" marker. */
        if (pe_is_container(in_path)) {
            if (pe_decrypt_file(in_path, out_path.string(), oo)) {
                std::cerr << "decrypted (pe): " << in_path << " -> " << out_path.string() << "\n";
            } else {
                std::cerr << "tesseract-crypt decrypt: failed on " << in_path << "\n";
                rc = EXIT_FAIL;
            }
            continue;
        }

        tess_open_file_options fo;
        tess_open_file_options_init(&fo);
        fo.recipient_secret = oo.recipient_secret;
        fo.passphrase = oo.passphrase;
        fo.required_signer = oo.required_signer;
        if (tess_open_file(in_path.c_str(), out_path.string().c_str(), &fo) == TESS_OK) {
            std::cerr << "decrypted: " << in_path << " -> " << out_path.string() << "\n";
        } else {
            std::cerr << "tesseract-crypt decrypt: failed on " << in_path << "\n";
            rc = EXIT_FAIL;
        }
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* commands                                                            */
/* ------------------------------------------------------------------ */

int cmd_help() {
    std::cout <<
        "tesseract-crypt " << tess_version() << " - string & file encryption with public/private keys\n"
        "\n"
        "Usage:\n"
        "  tesseract-crypt keygen   -o NAME [--passphrase] [--kdf-ops N] [--kdf-mem MB]\n"
        "      Generate NAME.key (private) and NAME.pub (public).\n"
        "\n"
        "  tesseract-crypt pubkey   -k KEYFILE [-o OUT]\n"
        "      Export the public key from a private key file.\n"
        "\n"
        "  tesseract-crypt encrypt  -r RECIPIENT.pub [-r MORE.pub ...] [-k SENDER.key] [-i IN] [-o OUT]\n"
        "                   [--armor] [--chunk-size N] [--no-sign] [--pe] [--pe-chunk-size MB]\n"
        "      Repeat -r to encrypt for several recipients at once.\n"
        "  tesseract-crypt encrypt  --dir DIR [-r RECIPIENT.pub] [-o OUTDIR] [--recursive]\n"
        "                   [--armor] [--pe] [--pe-chunk-size MB]\n"
        "      Encrypt every file of a directory.  --recursive also walks the\n"
        "      subdirectories and keeps the tree in the output directory.\n"
        "  tesseract-crypt encrypt  --passphrase [--text \"secret\"] [-i IN] [-o OUT] [--armor]\n"
        "  tesseract-crypt encrypt  --text \"secret\" -r RECIPIENT.pub\n"
        "      Encrypt a file or a string.  Default input/output: stdin/stdout.\n"
        "      Output to a TTY is automatically armored.\n"
        "\n"
        "  tesseract-crypt decrypt  -k RECIPIENT.key [-i IN] [-o OUT]\n"
        "                   [--require-signer SIGNER.pub] [--passphrase]\n"
        "      Decrypt a message.  Armored input is auto-detected.\n"
        "  tesseract-crypt decrypt  --dir DIR -k RECIPIENT.key [-o OUTDIR] [--recursive]\n"
        "      Decrypt every file of a directory.  A \"PE\" container is\n"
        "      recognised automatically and unpacked.\n"
        "\n"
        "  tesseract-crypt sign     -k KEY [-i FILE] [-o FILE.sig]\n"
        "  tesseract-crypt verify   -k PUBKEY -i FILE -s FILE.sig\n"
        "\n"
        "  tesseract-crypt inspect  [-i FILE]     Show the message header.\n"
        "  tesseract-crypt info     -k KEYFILE    Show key type and fingerprint.\n"
        "  tesseract-crypt version                Print version.\n"
        "  tesseract-crypt help                   This help.\n"
        "\n"
        "Exit codes: 0 success, 1 error, 2 usage, 3 authentication failure.\n";
    return EXIT_OK;
}

int cmd_version() {
    std::cout << "tesseract-crypt " << tess_version() << "\n";
    return EXIT_OK;
}

int cmd_keygen(const parser &p) {
    std::string name = p.get("-o");
    if (name.empty()) {
        std::cerr << "tesseract-crypt keygen: missing -o NAME\n";
        return EXIT_USAGE;
    }
    /* strip a trailing .key if the user typed one */
    if (name.size() > 4 && name.compare(name.size() - 4, 4, ".key") == 0) {
        name.resize(name.size() - 4);
    }

    uint32_t ops = 0;
    uint64_t mem_mb = 0;
    if (!p.get_u32("--kdf-ops", ops) && p.has("--kdf-ops")) {
        std::cerr << "tesseract-crypt keygen: invalid --kdf-ops\n";
        return EXIT_USAGE;
    }
    if (!p.get_u64_mb("--kdf-mem", mem_mb) && p.has("--kdf-mem")) {
        std::cerr << "tesseract-crypt keygen: invalid --kdf-mem\n";
        return EXIT_USAGE;
    }
    uint64_t mem = mem_mb ? mem_mb * 1024ull * 1024ull : 0;

    tess_key *sec = nullptr, *pub = nullptr;
    tess_status st;

    if (p.has("--passphrase")) {
        std::string pass = getpass("Passphrase: ");
        if (pass.empty()) {
            std::cerr << "tesseract-crypt keygen: empty passphrase\n";
            return EXIT_USAGE;
        }
        std::string again = getpass("Confirm passphrase: ");
        if (pass != again) {
            std::cerr << "tesseract-crypt keygen: passphrases do not match\n";
            return EXIT_USAGE;
        }
        st = tess_keygen_locked(pass.c_str(), ops, mem, &sec, &pub);
    } else {
        st = tess_keygen(&sec, &pub);
    }
    if (st != TESS_OK) {
        fail(st, "keygen");
        return exit_for(st);
    }

    std::string priv_path = name + ".key";
    std::string pub_path = name + ".pub";
    st = tess_key_save(sec, priv_path.c_str());
    if (st == TESS_OK) st = tess_key_save(pub, pub_path.c_str());
    if (st != TESS_OK) {
        fail(st, "saving keys");
        tess_key_free(sec);
        tess_key_free(pub);
        return exit_for(st);
    }

    char fp[TESS_FINGERPRINT_HEX + 1];
    tess_key_fingerprint(pub, fp);
    std::cout << "private key : " << priv_path << "\n"
              << "public key  : " << pub_path << "\n"
              << "fingerprint : " << fp << "\n";
    tess_key_free(sec);
    tess_key_free(pub);
    return EXIT_OK;
}

int cmd_pubkey(const parser &p) {
    std::string path = p.get("-k");
    if (path.empty()) {
        std::cerr << "tesseract-crypt pubkey: missing -k KEYFILE\n";
        return EXIT_USAGE;
    }
    tess_key *k = nullptr;
    std::string pass;
    tess_status st = tess_key_load(path.c_str(), nullptr, &k);
    if (st == TESS_ERR_PASSPHRASE) {
        pass = getpass(("Passphrase for " + path + ": ").c_str());
        st = tess_key_load(path.c_str(), pass.c_str(), &k);
    }
    if (st != TESS_OK) {
        fail(st, "loading " + path);
        return exit_for(st);
    }

    tess_key *pub = nullptr;
    st = tess_key_get_public(k, &pub);
    tess_key_free(k);
    if (st != TESS_OK) {
        fail(st, "deriving public key");
        return exit_for(st);
    }

    std::string out = p.get("-o");
    if (out.empty()) {
        out = path;
        if (out.size() > 4 && out.compare(out.size() - 4, 4, ".key") == 0) {
            out.resize(out.size() - 4);
        }
        out += ".pub";
    }
    st = tess_key_save(pub, out.c_str());
    if (st != TESS_OK) {
        fail(st, "saving " + out);
        tess_key_free(pub);
        return exit_for(st);
    }
    char fp[TESS_FINGERPRINT_HEX + 1];
    tess_key_fingerprint(pub, fp);
    std::cout << "public key  : " << out << "\n"
              << "fingerprint : " << fp << "\n";
    tess_key_free(pub);
    return EXIT_OK;
}

/* load a key file, prompting for the passphrase when locked */
tess_status load_key(const std::string &path, const std::string &pass_opt,
                     bool allow_prompt, tess_key **out) {
    tess_status st = tess_key_load(path.c_str(),
                                   pass_opt.empty() ? nullptr : pass_opt.c_str(),
                                   out);
    if (st == TESS_ERR_PASSPHRASE && allow_prompt) {
        std::string pass = getpass(("Passphrase for " + path + ": ").c_str());
        st = tess_key_load(path.c_str(), pass.c_str(), out);
    }
    return st;
}

int cmd_encrypt(const parser &p) {
    tess_seal_options so;
    tess_seal_options_init(&so);

    const bool dir_mode = p.has("--dir");
    const bool passphrase_mode = p.has("--passphrase");

    if (dir_mode) {
        /* Batch mode: every file of a directory.  The keys are loaded once
         * and reused for the whole batch. */
        std::vector<std::string> rec_paths = p.get_all("-r");
        if (rec_paths.empty() && !passphrase_mode) {
            std::cerr << "tesseract-crypt encrypt: need -r RECIPIENT.pub or --passphrase\n";
            return EXIT_USAGE;
        }

        std::vector<tess_key *> rec_pubs;
        std::vector<const tess_key *> rec_view;
        tess_status st = TESS_OK;
        for (const std::string &rp : rec_paths) {
            tess_key *k = nullptr;
            st = tess_key_load(rp.c_str(), nullptr, &k);
            if (st != TESS_OK) {
                fail(st, "loading " + rp);
                for (tess_key *kk : rec_pubs) tess_key_free(kk);
                return exit_for(st);
            }
            rec_pubs.push_back(k);
        }
        for (tess_key *k : rec_pubs) rec_view.push_back(k);
        if (rec_pubs.size() == 1) {
            so.recipient_public = rec_pubs[0];
        } else if (!rec_pubs.empty()) {
            so.recipients = rec_view.data();
            so.recipient_count = rec_view.size();
        }

        tess_key *sender = nullptr;
        if (!p.get("-k").empty()) {
            std::string pass;
            st = load_key(p.get("-k"), pass, true, &sender);
            if (st != TESS_OK) {
                fail(st, "loading " + p.get("-k"));
                for (tess_key *kk : rec_pubs) tess_key_free(kk);
                return exit_for(st);
            }
            if (tess_key_is_locked(sender)) {
                fail(TESS_ERR_PASSPHRASE, "sender key is locked");
                for (tess_key *kk : rec_pubs) tess_key_free(kk);
                tess_key_free(sender);
                return EXIT_AUTH;
            }
            so.sender_secret = sender;
            so.sign = p.has("--no-sign") ? 0 : 1;
        } else {
            so.sign = 0;
        }

        uint32_t chunk = 0;
        if (p.get_u32("--chunk-size", chunk)) {
            so.chunk_size = chunk;
        } else if (p.has("--chunk-size")) {
            std::cerr << "tesseract-crypt encrypt: invalid --chunk-size\n";
            for (tess_key *kk : rec_pubs) tess_key_free(kk);
            tess_key_free(sender);
            return EXIT_USAGE;
        }

        std::string passphrase;
        if (passphrase_mode) {
            passphrase = getpass("Passphrase: ");
            if (passphrase.empty()) {
                std::cerr << "tesseract-crypt encrypt: empty passphrase\n";
                for (tess_key *kk : rec_pubs) tess_key_free(kk);
                tess_key_free(sender);
                return EXIT_USAGE;
            }
        }

        const int rc = cmd_encrypt_batch(p, so, passphrase_mode, passphrase);
        for (tess_key *kk : rec_pubs) tess_key_free(kk);
        tess_key_free(sender);
        return rc;
    }

    std::vector<std::string> rec_paths = p.get_all("-r");
    std::vector<tess_key *> rec_pubs;
    std::vector<const tess_key *> rec_view;
    std::string sender_path = p.get("-k");
    bool do_sign = !p.has("--no-sign");

    tess_key *sender = nullptr;
    tess_key *sender_pub = nullptr;
    tess_status st = TESS_OK;
    int rc = EXIT_OK;
    uint32_t chunk = 0;

    if (!rec_paths.empty() && passphrase_mode) {
        std::cerr << "tesseract-crypt encrypt: use either -r or --passphrase, not both\n";
        return EXIT_USAGE;
    }
    if (rec_paths.empty() && !passphrase_mode) {
        std::cerr << "tesseract-crypt encrypt: need -r RECIPIENT.pub or --passphrase\n";
        return EXIT_USAGE;
    }

    if (!rec_paths.empty()) {
        /* load every recipient; repeat -r to encrypt for several at once */
        for (const std::string &rp : rec_paths) {
            tess_key *k = nullptr;
            st = tess_key_load(rp.c_str(), nullptr, &k);
            if (st != TESS_OK) {
                fail(st, "loading " + rp);
                for (tess_key *kk : rec_pubs) tess_key_free(kk);
                return exit_for(st);
            }
            rec_pubs.push_back(k);
        }
        rec_view.reserve(rec_pubs.size());
        for (tess_key *k : rec_pubs) rec_view.push_back(k);
        if (rec_pubs.size() == 1) {
            so.recipient_public = rec_pubs[0]; /* single recipient: v1 */
        } else {
            so.recipients = rec_view.data();   /* multi-recipient: v2 */
            so.recipient_count = rec_view.size();
        }

        if (!sender_path.empty()) {
            std::string pass;
            st = load_key(sender_path, pass, true, &sender);
            if (st != TESS_OK) {
                fail(st, "loading " + sender_path);
                goto cleanup;
            }
            if (tess_key_is_locked(sender)) {
                fail(TESS_ERR_PASSPHRASE, "sender key is locked");
                rc = EXIT_AUTH;
                goto cleanup;
            }
            so.sender_secret = sender;
            st = tess_key_get_public(sender, &sender_pub);
            if (st != TESS_OK) {
                fail(st, "sender public part");
                rc = exit_for(st);
                goto cleanup;
            }
        }
        if (do_sign && so.sender_secret == nullptr) {
            do_sign = false; /* signing requires -k sender.key */
        }
    } else {
        std::string pass = getpass("Passphrase: ");
        if (pass.empty()) {
            std::cerr << "tesseract-crypt encrypt: empty passphrase\n";
            return EXIT_USAGE;
        }
        so.passphrase = pass.c_str();
        /* keep alive for the duration of the call */
        so.sign = 0;
        uint32_t cs = 0;
        if (p.get_u32("--chunk-size", cs)) {
            so.chunk_size = cs;
        } else if (p.has("--chunk-size")) {
            std::cerr << "tesseract-crypt encrypt: invalid --chunk-size\n";
            return EXIT_USAGE;
        }

        std::string text = p.get("--text");
        bool have_text = p.has("--text");
        std::string in_path = p.get("-i", have_text ? "" : "-");
        std::string out_path = p.get("-o", "-");

        /* --pe with a passphrase: the container is written by the same
         * chunk loop as for recipients. */
        if (!have_text && in_path != "-" && out_path != "-" && p.has("--pe")) {
            uint64_t pe_mb = 256;
            if (!p.get_u64("--pe-chunk-size", pe_mb) && p.has("--pe-chunk-size")) {
                std::cerr << "tesseract-crypt encrypt: invalid --pe-chunk-size\n";
                return EXIT_USAGE;
            }
            if (pe_mb > 1024ull) pe_mb = 1024ull;
            if (!pe_encrypt_file(in_path, out_path, so, p.has("--armor"), pe_mb)) {
                fail(TESS_ERR_IO, "encrypt " + in_path);
                remove_part(out_path);
                return EXIT_FAIL;
            }
            return EXIT_OK;
        }

        std::string data;
        if (have_text) {
            data = text;
        } else if (!read_input(in_path, data)) {
            return EXIT_FAIL;
        }

        bool arm = p.has("--armor") ||
                   (out_path == "-" && (stdout_tty() || have_text));
        uint8_t *ct = nullptr;
        size_t ct_len = 0;
        st = tess_seal(reinterpret_cast<const uint8_t *>(data.data()),
                       data.size(), &so, &ct, &ct_len);
        if (st != TESS_OK) {
            fail(st, "encrypt");
            remove_part(out_path);
            return exit_for(st);
        }
        std::string out;
        if (arm) {
            char *txt = nullptr;
            st = tess_armor(ct, ct_len, "TESSERACT MESSAGE", &txt);
            tess_free(ct);
            if (st != TESS_OK) {
                fail(st, "armor");
                return exit_for(st);
            }
            out.assign(txt);
            tess_free(txt);
        } else {
            out.assign(reinterpret_cast<const char *>(ct), ct_len);
            tess_free(ct);
        }
        if (!write_output(out_path, out)) return EXIT_FAIL;
        return EXIT_OK;
    }

    so.sign = do_sign ? 1 : 0;

    if (p.get_u32("--chunk-size", chunk)) so.chunk_size = chunk;
    else if (p.has("--chunk-size")) {
        std::cerr << "tesseract-crypt encrypt: invalid --chunk-size\n";
        rc = EXIT_USAGE;
        goto cleanup;
    }

    {
        std::string text = p.get("--text");
        bool have_text = p.has("--text");
        std::string in_path = p.get("-i", have_text ? "" : "-");
        std::string out_path = p.get("-o", "-");
        bool arm = p.has("--armor") ||
                   (out_path == "-" && (stdout_tty() || have_text));

        if (have_text) {
            uint8_t *ct = nullptr;
            size_t ct_len = 0;
            st = tess_seal(reinterpret_cast<const uint8_t *>(text.data()),
                           text.size(), &so, &ct, &ct_len);
            if (st != TESS_OK) {
                fail(st, "encrypt");
                rc = exit_for(st);
                goto cleanup;
            }
            std::string out;
            if (arm) {
                char *txt = nullptr;
                st = tess_armor(ct, ct_len, "TESSERACT MESSAGE", &txt);
                tess_free(ct);
                if (st != TESS_OK) {
                    fail(st, "armor");
                    rc = exit_for(st);
                    goto cleanup;
                }
                out.assign(txt);
                tess_free(txt);
            } else {
                out.assign(reinterpret_cast<const char *>(ct), ct_len);
                tess_free(ct);
            }
            if (!write_output(out_path, out)) rc = EXIT_FAIL;
            goto cleanup;
        }

        if (in_path != "-" && out_path != "-" && p.has("--pe")) {
            /* --pe: the file becomes a container of sealed chunks */
            uint64_t pe_mb = 256;
            if (!p.get_u64("--pe-chunk-size", pe_mb) && p.has("--pe-chunk-size")) {
                std::cerr << "tesseract-crypt encrypt: invalid --pe-chunk-size\n";
                rc = EXIT_USAGE;
                goto cleanup;
            }
            if (pe_mb > 1024ull) pe_mb = 1024ull;
            if (!pe_encrypt_file(in_path, out_path, so, arm, pe_mb)) {
                fail(TESS_ERR_IO, "encrypt " + in_path);
                remove_part(out_path);
                rc = EXIT_FAIL;
            }
            goto cleanup;
        } else if (in_path != "-" && out_path != "-" && !arm) {
            /* streaming file -> file */
            tess_seal_file_options fo;
            tess_seal_file_options_init(&fo);
            fo.recipient_public = so.recipient_public;
            fo.recipients = so.recipients;
            fo.recipient_count = so.recipient_count;
            fo.sender_secret = sender;
            fo.sign = so.sign;
            fo.chunk_size = so.chunk_size;
            st = tess_seal_file(in_path.c_str(), out_path.c_str(), &fo);
            if (st != TESS_OK) {
                fail(st, "encrypt " + in_path);
                remove_part(out_path);
                rc = exit_for(st);
            }
            goto cleanup;
        }

        std::string data;
        if (!read_input(in_path, data)) {
            rc = EXIT_FAIL;
            goto cleanup;
        }
        uint8_t *ct = nullptr;
        size_t ct_len = 0;
        st = tess_seal(reinterpret_cast<const uint8_t *>(data.data()),
                       data.size(), &so, &ct, &ct_len);
        if (st != TESS_OK) {
            fail(st, "encrypt");
            rc = exit_for(st);
            goto cleanup;
        }
        std::string out;
        if (arm) {
            char *txt = nullptr;
            st = tess_armor(ct, ct_len, "TESSERACT MESSAGE", &txt);
            tess_free(ct);
            if (st != TESS_OK) {
                fail(st, "armor");
                rc = exit_for(st);
                goto cleanup;
            }
            out.assign(txt);
            tess_free(txt);
        } else {
            out.assign(reinterpret_cast<const char *>(ct), ct_len);
            tess_free(ct);
        }
        if (!write_output(out_path, out)) rc = EXIT_FAIL;
    }

cleanup:
    for (tess_key *k : rec_pubs) tess_key_free(k);
    tess_key_free(sender);
    tess_key_free(sender_pub);
    return rc;
}

int cmd_decrypt(const parser &p) {
    tess_open_options oo;
    tess_open_options_init(&oo);

    std::string key_path = p.get("-k");
    std::string signer_path = p.get("--require-signer");
    bool passphrase_mode = p.has("--passphrase");

    tess_key *sec = nullptr;
    tess_key *req_signer = nullptr;
    tess_status st = TESS_OK;
    int rc = EXIT_OK;

    if (!key_path.empty() && passphrase_mode) {
        std::cerr << "tesseract-crypt decrypt: use either -k or --passphrase\n";
        return EXIT_USAGE;
    }
    if (key_path.empty() && !passphrase_mode) {
        std::cerr << "tesseract-crypt decrypt: need -k RECIPIENT.key or --passphrase\n";
        return EXIT_USAGE;
    }

    std::string pass;
    if (!key_path.empty()) {
        st = load_key(key_path, pass, true, &sec);
        if (st != TESS_OK) {
            fail(st, "loading " + key_path);
            return exit_for(st);
        }
        oo.recipient_secret = sec;
    } else {
        pass = getpass("Passphrase: ");
        if (pass.empty()) {
            std::cerr << "tesseract-crypt decrypt: empty passphrase\n";
            return EXIT_USAGE;
        }
        oo.passphrase = pass.c_str();
    }

    if (!signer_path.empty()) {
        st = tess_key_load(signer_path.c_str(), nullptr, &req_signer);
        if (st != TESS_OK) {
            fail(st, "loading " + signer_path);
            rc = exit_for(st);
            goto cleanup;
        }
        oo.required_signer = req_signer;
    }

    if (p.has("--dir")) {
        /* Batch mode: every file of a directory.  A "PE" container is
         * recognised by its marker and unpacked automatically. */
        oo.recipient_secret = sec;
        oo.passphrase = passphrase_mode ? pass.c_str() : nullptr;
        const int brc = cmd_decrypt_batch(p, oo, pass, passphrase_mode);
        tess_key_free(sec);
        tess_key_free(req_signer);
        return brc;
    }

    {
        std::string in_path = p.get("-i", "-");
        std::string out_path = p.get("-o", "-");
        int signed_flag = 0;
        oo.out_signed = &signed_flag;

        if (in_path != "-" && out_path != "-" && pe_is_container(in_path)) {
            /* a PE container: unpack it back into one plain file */
            oo.recipient_secret = sec;
            oo.passphrase = passphrase_mode ? pass.c_str() : nullptr;
            oo.required_signer = req_signer;
            if (!pe_decrypt_file(in_path, out_path, oo)) {
                fail(TESS_ERR_CRYPTO, "decrypt " + in_path);
                remove_part(out_path);
                rc = EXIT_FAIL;
                goto cleanup;
            }
        } else if (in_path != "-" && out_path != "-") {
            /* file -> file: streaming, atomic, verify-then-rename */
            tess_open_file_options fo;
            tess_open_file_options_init(&fo);
            fo.recipient_secret = sec;
            fo.passphrase = passphrase_mode ? pass.c_str() : nullptr;
            fo.required_signer = req_signer;
            fo.out_signed = &signed_flag;
            st = tess_open_file(in_path.c_str(), out_path.c_str(), &fo);
            if (st != TESS_OK) {
                fail(st, "decrypt " + in_path);
                remove_part(out_path);
                rc = exit_for(st);
                goto cleanup;
            }
        } else {
            /* stdin -> stdout, or file -> stdout: the plaintext goes to
             * stdout when no output file was requested */
            std::string data;
            if (!read_input(in_path, data)) {
                rc = EXIT_FAIL;
                goto cleanup;
            }
            if (tess_is_armored(reinterpret_cast<const uint8_t *>(data.data()),
                                data.size())) {
                uint8_t *raw = nullptr;
                size_t raw_len = 0;
                st = tess_dearmor(data.c_str(), &raw, &raw_len);
                if (st != TESS_OK) {
                    fail(st, "dearmor");
                    rc = exit_for(st);
                    goto cleanup;
                }
                data.assign(reinterpret_cast<const char *>(raw), raw_len);
                tess_free(raw);
            }
            uint8_t *pt = nullptr;
            size_t pt_len = 0;
            st = tess_open(reinterpret_cast<const uint8_t *>(data.data()),
                           data.size(), &oo, &pt, &pt_len);
            if (st != TESS_OK) {
                fail(st, "decrypt");
                rc = exit_for(st);
                goto cleanup;
            }
            std::string out(reinterpret_cast<const char *>(pt), pt_len);
            tess_free(pt);
            if (!write_output(out_path, out)) rc = EXIT_FAIL;
        }

        if (rc == EXIT_OK) {
            if (signed_flag) {
                std::cerr << "signature: OK\n";
            } else if (!signer_path.empty()) {
                std::cerr << "tesseract-crypt: message is not signed\n";
                rc = EXIT_AUTH;
            } else {
                std::cerr << "signature: none (message is unsigned)\n";
            }
        }
    }

cleanup:
    tess_key_free(sec);
    tess_key_free(req_signer);
    return rc;
}

int cmd_sign(const parser &p) {
    std::string key_path = p.get("-k");
    std::string in_path = p.get("-i", "-");
    std::string out_path = p.get("-o");
    if (key_path.empty()) {
        std::cerr << "tesseract-crypt sign: missing -k KEYFILE\n";
        return EXIT_USAGE;
    }
    if (out_path.empty()) {
        out_path = (in_path == "-") ? "-" : in_path + ".sig";
    }

    tess_key *sec = nullptr;
    std::string pass;
    tess_status st = load_key(key_path, pass, true, &sec);
    if (st != TESS_OK) {
        fail(st, "loading " + key_path);
        return exit_for(st);
    }

    uint8_t sig[TESS_SIGNATURE_BYTES];
    if (in_path == "-") {
        std::string data;
        if (!read_input("-", data)) {
            tess_key_free(sec);
            return EXIT_FAIL;
        }
        st = tess_sign(reinterpret_cast<const uint8_t *>(data.data()),
                       data.size(), sec, sig);
    } else {
        st = tess_sign_file(in_path.c_str(), sec, sig);
    }
    tess_key_free(sec);
    if (st != TESS_OK) {
        fail(st, "sign");
        return exit_for(st);
    }

    char *armored = nullptr;
    st = tess_armor(sig, sizeof sig, "TESSERACT SIGNATURE", &armored);
    if (st != TESS_OK) {
        fail(st, "armor");
        return exit_for(st);
    }
    bool ok = write_output(out_path, armored);
    tess_free(armored);
    if (!ok) return EXIT_FAIL;
    if (out_path != "-") std::cerr << "signature written to " << out_path << "\n";
    return EXIT_OK;
}

int cmd_verify(const parser &p) {
    std::string key_path = p.get("-k");
    std::string in_path = p.get("-i", "-");
    std::string sig_path = p.get("-s");
    if (key_path.empty() || sig_path.empty()) {
        std::cerr << "tesseract-crypt verify: need -k PUBKEY and -s SIGNATURE\n";
        return EXIT_USAGE;
    }

    tess_key *pub = nullptr;
    tess_status st = tess_key_load(key_path.c_str(), nullptr, &pub);
    if (st != TESS_OK) {
        fail(st, "loading " + key_path);
        return exit_for(st);
    }

    std::string sigdata;
    if (!read_input(sig_path, sigdata)) {
        tess_key_free(pub);
        return EXIT_FAIL;
    }
    uint8_t *sig = nullptr;
    size_t sig_len = 0;
    st = tess_dearmor(sigdata.c_str(), &sig, &sig_len);
    if (st != TESS_OK || sig_len != TESS_SIGNATURE_BYTES) {
        if (st == TESS_OK) st = TESS_ERR_FORMAT;
        fail(st, "reading signature " + sig_path);
        tess_key_free(pub);
        tess_free(sig);
        return exit_for(st);
    }

    if (in_path == "-") {
        std::string data;
        if (!read_input("-", data)) {
            tess_key_free(pub);
            tess_free(sig);
            return EXIT_FAIL;
        }
        st = tess_verify(reinterpret_cast<const uint8_t *>(data.data()),
                         data.size(), pub, sig);
    } else {
        st = tess_verify_file(in_path.c_str(), pub, sig);
    }
    tess_free(sig);
    tess_key_free(pub);
    if (st != TESS_OK) {
        fail(st, "verify");
        return exit_for(st);
    }
    std::cout << "signature: OK\n";
    return EXIT_OK;
}

int cmd_inspect(const parser &p) {
    std::string in_path = p.get("-i", "-");
    std::string data;
    if (!read_input(in_path, data)) return EXIT_FAIL;

    if (tess_is_armored(reinterpret_cast<const uint8_t *>(data.data()),
                        data.size())) {
        uint8_t *raw = nullptr;
        size_t raw_len = 0;
        tess_status st = tess_dearmor(data.c_str(), &raw, &raw_len);
        if (st != TESS_OK) {
            fail(st, "dearmor");
            return exit_for(st);
        }
        data.assign(reinterpret_cast<const char *>(raw), raw_len);
        tess_free(raw);
    }

    tess_message_info info;
    tess_status st =
        tess_inspect(reinterpret_cast<const uint8_t *>(data.data()),
                     data.size(), &info);
    if (st != TESS_OK) {
        fail(st, "inspect");
        return exit_for(st);
    }

    std::cout << "format version : " << info.version << "\n"
              << "suite          : " << info.suite << "\n"
              << "mode           : "
              << (info.mode == TESS_MODE_PUBLICKEY ? "public-key"
                                                   : "passphrase")
              << "\n";
    if (info.mode == TESS_MODE_PUBLICKEY) {
        std::cout << "recipients     : " << info.recipient_count << "\n";
    }
    std::cout << "signed         : " << (info.signed_flag ? "yes" : "no")
              << "\n"
              << "chunk size     : " << info.chunk_size << " bytes\n"
              << "plaintext len  : ";
    if (info.plaintext_len == UINT64_MAX) std::cout << "unknown\n";
    else std::cout << info.plaintext_len << " bytes\n";
    std::cout << "sender key     : "
              << (info.has_sender ? "present" : "anonymous") << "\n";
    if (info.signed_flag) {
        std::cout << "signer fp      : " << info.fingerprint << "\n";
    }
    return EXIT_OK;
}

int cmd_info(const parser &p) {
    std::string key_path = p.get("-k");
    if (key_path.empty()) {
        std::cerr << "tesseract-crypt info: missing -k KEYFILE\n";
        return EXIT_USAGE;
    }
    tess_key *k = nullptr;
    std::string pass;
    tess_status st = load_key(key_path, pass, false, &k);
    if (st == TESS_ERR_PASSPHRASE) {
        /* locked key: we can still read the public half by prompting */
        pass = getpass(("Passphrase for " + key_path + ": ").c_str());
        st = tess_key_load(key_path.c_str(), pass.c_str(), &k);
    }
    if (st != TESS_OK) {
        fail(st, "loading " + key_path);
        return exit_for(st);
    }

    char fp[TESS_FINGERPRINT_HEX + 1];
    st = tess_key_fingerprint(k, fp);
    if (st != TESS_OK) {
        fail(st, "fingerprint");
        tess_key_free(k);
        return exit_for(st);
    }

    const char *kind;
    if (!tess_key_is_secret(k)) kind = "public";
    else if (tess_key_is_locked(k)) kind = "private (locked)";
    else kind = "private (unlocked)";

    std::cout << "key file       : " << key_path << "\n"
              << "type           : " << kind << "\n"
              << "fingerprint    : " << fp << "\n";
    tess_key_free(k);
    return EXIT_OK;
}

} // namespace

/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    if (sodium_init() < 0) {
        std::cerr << "tesseract-crypt: libsodium initialization failed\n";
        return EXIT_FAIL;
    }
    if (argc < 2) return cmd_help();

    parser p(argc, argv);
    const std::string &cmd = p.cmd;

    if (cmd == "help" || cmd == "--help" || cmd == "-h") return cmd_help();
    if (cmd == "version" || cmd == "--version" || cmd == "-V") {
        return cmd_version();
    }
    if (cmd == "keygen") return cmd_keygen(p);
    if (cmd == "pubkey") return cmd_pubkey(p);
    if (cmd == "encrypt") return cmd_encrypt(p);
    if (cmd == "decrypt") return cmd_decrypt(p);
    if (cmd == "sign") return cmd_sign(p);
    if (cmd == "verify") return cmd_verify(p);
    if (cmd == "inspect") return cmd_inspect(p);
    if (cmd == "info") return cmd_info(p);

    std::cerr << "tesseract-crypt: unknown command '" << cmd << "'\n";
    cmd_help();
    return EXIT_USAGE;
}
