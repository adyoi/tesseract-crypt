#!/bin/sh
# scripts/bench.sh - reproducible throughput benchmark for the tesseract-crypt CLI.
#
# Usage:  scripts/bench.sh [BIN] [SIZE_MB]
#   BIN       path to the tesseract-crypt / tscrypt binary (default ./build/tscrypt)
#   SIZE_MB   payload size in MiB for the streaming tests  (default 16)
#   REPS      repeats per measurement, best (min) kept       (default 3)
#
# It prints a Markdown table with wall-clock time and MiB/s for every mode.
# Numbers depend on CPU, OS and build flags (Release recommended); antivirus
# scanning on Windows can dominate the first run, which is why the best of
# REPS runs is reported.  Treat the table as an order-of-magnitude reference,
# not a guarantee.
set -eu

BIN=${1:-./build/tscrypt}
SIZE_MB=${2:-16}
REPS=${REPS:-3}

case "$BIN" in
    */*) ;;
    *) BIN="./$BIN" ;;
esac
[ -x "$BIN" ] || { echo "bench: not executable: $BIN" >&2; exit 1; }

now_ns() {
    n=$(date +%s%N 2>/dev/null || true)
    case "$n" in
        ''|*[!0-9]*) echo "$(( $(date +%s) * 1000000000 ))" ;;
        *) echo "$n" ;;
    esac
}

# best-of-N wall-clock milliseconds for a command (infile supplies stdin)
tmin() {
    reps=$1; infile=$2; shift 2
    best=''
    i=0
    while [ "$i" -lt "$reps" ]; do
        t0=$(now_ns)
        "$@" < "$infile" >/dev/null 2>&1 || true
        d=$(( ($(now_ns) - t0) / 1000000 ))
        if [ -z "$best" ] || [ "$d" -lt "$best" ]; then best=$d; fi
        i=$((i + 1))
    done
    echo "$best"
}

mbps() { awk -v b="$1" -v ms="$2" 'BEGIN { if (ms <= 0) ms = 1; printf "%.0f", (b / 1048576) / (ms / 1000) }'; }

WORK=$(mktemp -d 2>/dev/null || mktemp -d -t tscryptbench)
trap 'rm -rf "$WORK"' EXIT INT TERM
cd "$WORK" || exit 1

BYTES=$((SIZE_MB * 1024 * 1024))
head -c "$BYTES" /dev/urandom > big.bin 2>/dev/null || dd if=/dev/urandom of=big.bin bs=1048576 count="$SIZE_MB" >/dev/null 2>&1
head -c 1024 /dev/urandom > small.bin 2>/dev/null || dd if=/dev/urandom of=small.bin bs=1024 count=1 >/dev/null 2>&1

printf 'bench-pass\n' > pw1
printf 'bench-pass\nbench-pass\n' > pw2

"$BIN" keygen -o bob >/dev/null 2>&1

keygen_ms=$(tmin "$REPS" /dev/null "$BIN" keygen -o alice)
lock_ms=$(tmin "$REPS" pw2 "$BIN" keygen -o lock --passphrase)
enc_ms=$(tmin "$REPS" /dev/null "$BIN" encrypt -r bob.pub -k alice.key -i big.bin -o big.enc)
dec_ms=$(tmin "$REPS" /dev/null "$BIN" decrypt -k bob.key -i big.enc -o big.out)
penc_ms=$(tmin "$REPS" pw1 "$BIN" encrypt --passphrase -i big.bin -o pass.enc)
pdec_ms=$(tmin "$REPS" pw1 "$BIN" decrypt --passphrase -i pass.enc -o pass.out)
sign_ms=$(tmin "$REPS" /dev/null "$BIN" sign -k alice.key -i big.bin -o big.sig)
ver_ms=$(tmin "$REPS" /dev/null "$BIN" verify -k alice.pub -i big.bin -s big.sig)
armor_ms=$(tmin "$REPS" /dev/null "$BIN" encrypt --armor -r bob.pub -i small.bin -o small.enc)
c4k_ms=$(tmin "$REPS" /dev/null "$BIN" encrypt -r bob.pub -k alice.key --chunk-size 4096 -i big.bin -o c4k.enc)
c64k_ms=$(tmin "$REPS" /dev/null "$BIN" encrypt -r bob.pub -k alice.key --chunk-size 65536 -i big.bin -o c64k.enc)
c1m_ms=$(tmin "$REPS" /dev/null "$BIN" encrypt -r bob.pub -k alice.key --chunk-size 1048576 -i big.bin -o c1m.enc)
multi_enc_ms=$(tmin "$REPS" /dev/null "$BIN" encrypt -r alice.pub -r bob.pub -r alice.pub -k alice.key -i big.bin -o multi.enc)
multi_dec_ms=$(tmin "$REPS" /dev/null "$BIN" decrypt -k bob.key -i multi.enc -o multi.out)

cmp -s big.bin big.out || { echo "bench: roundtrip mismatch" >&2; exit 1; }

cat <<EOF
Host: $("$BIN" version 2>/dev/null | head -n1) | payload ${SIZE_MB} MiB | best of ${REPS} | $(uname -s 2>/dev/null || echo unknown)

| Operation | Payload | Time | Throughput |
|-----------|---------|------|------------|
| keygen (X25519 + Ed25519) | - | ${keygen_ms} ms | - |
| keygen \`--passphrase\` (Argon2id moderate) | 96 B blob | ${lock_ms} ms | - |
| encrypt (public-key, signed) | ${SIZE_MB} MiB | ${enc_ms} ms | $(mbps "$BYTES" "$enc_ms") MiB/s |
| decrypt (public-key, verify sign) | ${SIZE_MB} MiB | ${dec_ms} ms | $(mbps "$BYTES" "$dec_ms") MiB/s |
| encrypt (\`--passphrase\`, Argon2id) | ${SIZE_MB} MiB | ${penc_ms} ms | $(mbps "$BYTES" "$penc_ms") MiB/s |
| decrypt (\`--passphrase\`) | ${SIZE_MB} MiB | ${pdec_ms} ms | $(mbps "$BYTES" "$pdec_ms") MiB/s |
| sign (Ed25519ph, streaming) | ${SIZE_MB} MiB | ${sign_ms} ms | $(mbps "$BYTES" "$sign_ms") MiB/s |
| verify (Ed25519ph, streaming) | ${SIZE_MB} MiB | ${ver_ms} ms | $(mbps "$BYTES" "$ver_ms") MiB/s |
| encrypt \`--armor\` | 1 KiB | ${armor_ms} ms | - |
| encrypt \`--chunk-size 4096\` | ${SIZE_MB} MiB | ${c4k_ms} ms | $(mbps "$BYTES" "$c4k_ms") MiB/s |
| encrypt \`--chunk-size 65536\` (default) | ${SIZE_MB} MiB | ${c64k_ms} ms | $(mbps "$BYTES" "$c64k_ms") MiB/s |
| encrypt \`--chunk-size 1048576\` | ${SIZE_MB} MiB | ${c1m_ms} ms | $(mbps "$BYTES" "$c1m_ms") MiB/s |
| encrypt, 3 recipients (format v2) | ${SIZE_MB} MiB | ${multi_enc_ms} ms | $(mbps "$BYTES" "$multi_enc_ms") MiB/s |
| decrypt, 3 recipients | ${SIZE_MB} MiB | ${multi_dec_ms} ms | $(mbps "$BYTES" "$multi_dec_ms") MiB/s |
EOF
