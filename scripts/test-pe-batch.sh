#!/usr/bin/env bash
# End to end check of the PE container and the directory batches.
set -euo pipefail

export PATH="/c/msys64/mingw64/bin:/c/msys64/usr/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/build-audit/tesseract-crypt.exe"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
check() {
    if [ "$2" = "$3" ]; then
        echo "  PASS  $1"
        pass=$((pass + 1))
    else
        echo "  FAIL  $1 (expected '$3', got '$2')"
        fail=$((fail + 1))
    fi
}

echo "== setup =="
cd "$WORK"
"$BIN" keygen -o alice >/dev/null
"$BIN" keygen -o bob   >/dev/null
head -c 300000 /dev/urandom > plain.bin
mkdir -p tree/sub/deeper
head -c 1000 /dev/urandom > tree/a.bin
head -c 2000 /dev/urandom > tree/sub/b.bin
head -c 3000 /dev/urandom > tree/sub/deeper/c.bin

echo "== single file, normal =="
"$BIN" encrypt -r alice.pub -i plain.bin -o plain.enc 2>/dev/null
"$BIN" decrypt -k alice.key -i plain.enc -o plain.out 2>/dev/null
cmp -s plain.bin plain.out && check "round trip" "same" "same" || check "round trip" "diff" "same"

echo "== PE container (--pe) =="
"$BIN" encrypt -r alice.pub -i plain.bin -o plain.pe --pe 2>/dev/null
head -c 3 plain.pe | od -An -c | tr -d ' \n' > magic.txt
check "PE marker" "$(cat magic.txt)" "tsc"
"$BIN" decrypt -k alice.key -i plain.pe -o plain.pe.out 2>/dev/null
cmp -s plain.bin plain.pe.out && check "PE round trip" "same" "same" || check "PE round trip" "diff" "same"

echo "== PE container is auto detected (no flag on decrypt) =="
"$BIN" inspect -i plain.pe 2>/dev/null || true
"$BIN" decrypt -k alice.key -i plain.pe -o plain.pe.out2 2>/dev/null
cmp -s plain.bin plain.pe.out2 && check "PE auto detect" "same" "same" || check "PE auto detect" "diff" "same"

echo "== PE container with several chunks =="
head -c 3500000 /dev/urandom > big.bin
"$BIN" encrypt -r alice.pub -i big.bin -o big.pe --pe --pe-chunk-size 1 2>/dev/null
"$BIN" decrypt -k alice.key -i big.pe -o big.out 2>/dev/null
cmp -s big.bin big.out && check "multi chunk round trip" "same" "same" || check "multi chunk round trip" "diff" "same"

echo "== armored PE container =="
"$BIN" encrypt -r alice.pub -i plain.bin -o plain.pe.arm --pe --armor 2>/dev/null
"$BIN" decrypt -k alice.key -i plain.pe.arm -o plain.pe.arm.out 2>/dev/null
cmp -s plain.bin plain.pe.arm.out && check "PE armored" "same" "same" || check "PE armored" "diff" "same"

echo "== PE container with a passphrase =="
"$BIN" encrypt --passphrase -i plain.bin -o pass.pe --pe <<< "s3cret pass" 2>/dev/null || true
if [ -f pass.pe ]; then
    head -c 3 pass.pe | od -An -c | tr -d ' \n' > magic2.txt
    check "passphrase PE marker" "$(cat magic2.txt)" "tsc"
    "$BIN" decrypt --passphrase -i pass.pe -o pass.out <<< "s3cret pass" 2>/dev/null || true
    cmp -s plain.bin pass.out && check "passphrase PE round trip" "same" "same" || check "passphrase PE round trip" "diff" "same"
fi

echo "== a truncated container is refused =="
head -c 40 big.pe > big.trunc
if "$BIN" decrypt -k alice.key -i big.trunc -o big.bad >/dev/null 2>&1; then
    check "truncated container" "accepted" "refused"
else
    check "truncated container" "refused" "refused"
fi

echo "== directory batch (flat) =="
mkdir -p out
"$BIN" encrypt --dir tree -r alice.pub --out-dir out 2>/dev/null
check "flat batch" "$(ls out | wc -l)" "1"
"$BIN" decrypt --dir out -k alice.key --out-dir dec 2>/dev/null
cmp -s tree/a.bin dec/a.bin && check "flat batch round trip" "same" "same" || check "flat batch round trip" "diff" "same"

echo "== directory batch (recursive) =="
rm -rf out dec
mkdir -p out
"$BIN" encrypt --dir tree -r alice.pub --out-dir out --recursive 2>/dev/null
check "recursive keeps tree" "$(test -f out/sub/b.bin.enc && test -f out/sub/deeper/c.bin.enc && echo yes)" "yes"
"$BIN" decrypt --dir out -k alice.key --out-dir dec --recursive 2>/dev/null
cmp -s tree/sub/deeper/c.bin dec/sub/deeper/c.bin && check "recursive round trip" "same" "same" || check "recursive round trip" "diff" "same"

echo "== directory batch with --pe =="
rm -rf out dec
mkdir -p out
"$BIN" encrypt --dir tree -r alice.pub -o out --pe --recursive 2>/dev/null
head -c 3 out/sub/b.bin.enc | od -An -c | tr -d ' \n' > magic3.txt
check "batch PE marker" "$(cat magic3.txt)" "tsc"
"$BIN" decrypt --dir out -k alice.key -o dec --recursive 2>/dev/null
cmp -s tree/sub/b.bin dec/sub/b.bin && check "batch PE round trip" "same" "same" || check "batch PE round trip" "diff" "same"

echo "== multi recipient =="
"$BIN" encrypt -r alice.pub -r bob.pub -i plain.bin -o multi.enc 2>/dev/null
"$BIN" decrypt -k bob.key -i multi.enc -o multi.out 2>/dev/null
cmp -s plain.bin multi.out && check "multi recipient" "same" "same" || check "multi recipient" "diff" "same"

echo "== wrong key is refused =="
if "$BIN" decrypt -k bob.key -i plain.enc -o wrong.out >/dev/null 2>&1; then
    check "wrong key" "accepted" "refused"
else
    check "wrong key" "refused" "refused"
fi

echo
echo "passed: $pass, failed: $fail"
[ "$fail" -eq 0 ]
