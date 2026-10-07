# cli_test.cmake — CLI end-to-end regression suite.
#
# Run by CTest as:  cmake -DTESS_CLI_EXE=<path> -P tests/cli_test.cmake
#
# Exercises the error-contract and I/O guarantees the CLI now promises:
#   * unknown flags / missing values exit with code 2
#   * keygen refuses to overwrite unless --force is given
#   * binary plaintext survives stdin/stdout pipes byte-for-byte
#     (incl. CRLF pairs and a 0x1A Ctrl-Z byte on Windows)
#   * decrypt -i FILE with no -o writes plaintext to stdout
#   * rekey --old-passphrase-file and --kdf-ops/--kdf-mem passphrase mode
#
# Byte comparisons read both files raw via the HEX form of file(READ),
# which is lossless and independent of CMake's own newline handling.

if(NOT DEFINED TESS_CLI_EXE)
    message(FATAL_ERROR "TESS_CLI_EXE must point at the built CLI binary")
endif()
if(NOT DEFINED WORK_DIR)
    message(FATAL_ERROR "WORK_DIR (a writable scratch root) is required")
endif()

set(WORK "${WORK_DIR}/cli-e2e")
file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")

set(FAILS "")
set(PASSES 0)

# ------------------------------------------------------------------ #
# helpers                                                             #
# ------------------------------------------------------------------ #

# cli_f(<code_var> <out_file> <err_file> <args...>) — no stdin
function(cli_f code_var out_file err_file)
    execute_process(COMMAND "${TESS_CLI_EXE}" ${ARGN}
        WORKING_DIRECTORY "${WORK}"
        OUTPUT_FILE "${WORK}/${out_file}"
        ERROR_FILE "${WORK}/${err_file}"
        RESULT_VARIABLE rc)
    set(${code_var} "${rc}" PARENT_SCOPE)
endfunction()

# cli_in(<code_var> <in_file> <out_file> <err_file> <args...>) — stdin from file
function(cli_in code_var in_file out_file err_file)
    execute_process(COMMAND "${TESS_CLI_EXE}" ${ARGN}
        WORKING_DIRECTORY "${WORK}"
        INPUT_FILE "${WORK}/${in_file}"
        OUTPUT_FILE "${WORK}/${out_file}"
        ERROR_FILE "${WORK}/${err_file}"
        RESULT_VARIABLE rc)
    set(${code_var} "${rc}" PARENT_SCOPE)
endfunction()

function(check_code name want got)
    if(NOT "${got}" STREQUAL "${want}")
        list(APPEND FAILS "${name}: exit ${got}, wanted ${want}")
    else()
        math(EXPR PASSES "${PASSES} + 1")
    endif()
    set(FAILS "${FAILS}" PARENT_SCOPE)
    set(PASSES "${PASSES}" PARENT_SCOPE)
    message(STATUS "${name}: exit ${got}")
endfunction()

function(check_bytes name a b)
    if(NOT EXISTS "${WORK}/${a}" OR NOT EXISTS "${WORK}/${b}")
        list(APPEND FAILS "${name}: missing file (${a} / ${b})")
        message(STATUS "${name}: MISSING ${a} / ${b}")
        set(FAILS "${FAILS}" PARENT_SCOPE)
        return()
    endif()
    file(READ "${WORK}/${a}" ahex HEX)
    file(READ "${WORK}/${b}" bhex HEX)
    if(NOT "${ahex}" STREQUAL "${bhex}")
        list(APPEND FAILS "${name}: bytes differ (${ahex} != ${bhex})")
        message(STATUS "${name}: MISMATCH")
    else()
        math(EXPR PASSES "${PASSES} + 1")
        message(STATUS "${name}: ok")
    endif()
    set(FAILS "${FAILS}" PARENT_SCOPE)
    set(PASSES "${PASSES}" PARENT_SCOPE)
endfunction()

function(check_contains name file needle)
    file(READ "${WORK}/${file}" content)
    string(FIND "${content}" "${needle}" pos)
    if(pos LESS 0)
        list(APPEND FAILS "${name}: output lacks '${needle}'")
        message(STATUS "${name}: MISMATCH")
    else()
        math(EXPR PASSES "${PASSES} + 1")
        message(STATUS "${name}: ok")
    endif()
    set(FAILS "${FAILS}" PARENT_SCOPE)
    set(PASSES "${PASSES}" PARENT_SCOPE)
endfunction()

# ------------------------------------------------------------------ #
# payload: CRLF pairs + Ctrl-Z (0x1A) + 0xFF bytes                    #
# ------------------------------------------------------------------ #

string(ASCII 26 ctrlz)
string(ASCII 255 ff)
set(PAYLOAD "Hello\nworld${ctrlz}${ff}\n!")
file(WRITE "${WORK}/payload.bin" "${PAYLOAD}")
file(READ "${WORK}/payload.bin" payload_hex HEX)
message(STATUS "payload hex = ${payload_hex}")

# ------------------------------------------------------------------ #
# keygen: ownership, --force, locked key with KDF flags               #
# ------------------------------------------------------------------ #

cli_f(code0 k0.out k0.err keygen -o alice)
check_code("keygen creates alice.key/alice.pub" 0 "${code0}")
if(NOT EXISTS "${WORK}/alice.key" OR NOT EXISTS "${WORK}/alice.pub")
    list(APPEND FAILS "keygen did not create alice.key and alice.pub")
endif()

cli_f(code1 k1.out k1.err keygen -o alice)
check_code("keygen refuses to overwrite (exit 2)" 2 "${code1}")

cli_f(code2 k2.out k2.err keygen -o alice --force)
check_code("keygen --force overwrites (exit 0)" 0 "${code2}")

cli_f(code3 k3.out k3.err pubkey -k alice.key -o alice.pub)
check_code("pubkey exports alice.pub" 0 "${code3}")

# keygen --passphrase asks for the passphrase *and* a confirmation.
file(WRITE "${WORK}/pw.txt" "pw-test\npw-test")
cli_in(codekey pw.txt keygen.out keygen.err keygen -o locked --passphrase --kdf-ops 3 --kdf-mem 16)
check_code("keygen --passphrase --kdf-ops/--kdf-mem" 0 "${codekey}")
cli_in(codei pw.txt ki.out ki.err info -k locked.key)
check_code("info reads a locked key (unlocks via piped passphrase)" 0 "${codei}")
check_contains("info reports the unlocked kind" ki.out "unlocked")

# ------------------------------------------------------------------ #
# encrypt / decrypt file -> file                                      #
# ------------------------------------------------------------------ #

cli_f(codee e.out e.err encrypt -r alice.pub -i payload.bin -o msg.bin)
check_code("encrypt file->file" 0 "${codee}")

cli_f(coded d.out d.err decrypt -k alice.key -i msg.bin -o dec.bin)
check_code("decrypt file->file" 0 "${coded}")
check_bytes("file roundtrip preserves payload" dec.bin payload.bin)

# ------------------------------------------------------------------ #
# stdout paths and binary pipes                                       #
# ------------------------------------------------------------------ #

cli_f(codee2 e2.out e2.err encrypt -r alice.pub -i payload.bin -o -)
check_code("encrypt ciphertext to stdout" 0 "${codee2}")

cli_f(coded2 d2.out d2.err decrypt -k alice.key -i msg.bin)
check_code("decrypt -i without -o streams to stdout" 0 "${coded2}")
check_bytes("decrypt-to-stdout preserves payload" d2.out payload.bin)

cli_in(codee3 payload.bin e3.out e3.err encrypt -r alice.pub)
check_code("stdin encrypt (binary pipe)" 0 "${codee3}")
cli_f(coded3 d3.out d3.err decrypt -k alice.key -i e3.out)
check_code("decrypt stdin-encrypted message" 0 "${coded3}")
check_bytes("stdin/stdout roundtrip preserves CRLF+0x1A+0xFF" d3.out payload.bin)

# ------------------------------------------------------------------ #
# errors: unknown flag / missing value / global --help                #
# ------------------------------------------------------------------ #

cli_f(codeu u.out u.err encrypt --frobnicate -r alice.pub)
check_code("unknown flag exits 2" 2 "${codeu}")

cli_f(codem m.out m.err encrypt -r)
check_code("missing flag value exits 2" 2 "${codem}")

cli_f(codeh h.out h.err encrypt --help)
check_code("global --help exits 0" 0 "${codeh}")
check_contains("--help prints usage" h.out "Usage:")

# ------------------------------------------------------------------ #
# --text                                                              #
# ------------------------------------------------------------------ #

cli_f(codet txt.out txt.err encrypt --text "e2e text payload" -r alice.pub -o -)
check_code("encrypt --text" 0 "${codet}")
cli_f(codetd td.out td.err decrypt -k alice.key -i txt.out)
check_code("decrypt --text message" 0 "${codetd}")
file(WRITE "${WORK}/txt_expected.bin" "e2e text payload")
check_bytes("--text roundtrip matches" td.out txt_expected.bin)

# ------------------------------------------------------------------ #
# rekey --old-passphrase-file + --kdf-* passphrase mode               #
# ------------------------------------------------------------------ #

cli_in(codepw pw.txt pwe.out pwe.err encrypt --passphrase -i payload.bin)
check_code("encrypt --passphrase" 0 "${codepw}")

cli_f(coderk rk.out rk.err rekey --old-passphrase-file pw.txt -i pwe.out -r alice.pub -o rekeyed.bin)
check_code("rekey --old-passphrase-file" 0 "${coderk}")
cli_f(coderd rd.out rd.err decrypt -k alice.key -i rekeyed.bin -o rkdec.bin)
check_code("decrypt rekeyed message" 0 "${coderd}")
check_bytes("rekey roundtrip preserves payload" rkdec.bin payload.bin)

cli_in(codekdf pw.txt kde.out kde.err encrypt --passphrase --kdf-ops 3 --kdf-mem 16 -i payload.bin)
check_code("encrypt --passphrase --kdf-ops/--kdf-mem" 0 "${codekdf}")
cli_in(codekdfd pw.txt kdd.out kdd.err decrypt --passphrase -i kde.out)
check_code("decrypt kdf message" 0 "${codekdfd}")
check_bytes("kdf roundtrip preserves payload" kdd.out payload.bin)

# ------------------------------------------------------------------ #
# inspect (armored + binary)                                          #
# ------------------------------------------------------------------ #

cli_f(codei1 i1.out i1.err inspect -i msg.bin)
check_code("inspect binary" 0 "${codei1}")
check_contains("inspect reports format version" i1.out "format version")

cli_f(codeia ia.out ia.err encrypt -r alice.pub -i payload.bin --armor -o -)
check_code("encrypt --armor to stdout" 0 "${codeia}")
cli_f(codei2 i2.out i2.err inspect -i ia.out)
check_code("inspect armored" 0 "${codei2}")
check_contains("inspect armored reports format version" i2.out "format version")

# ------------------------------------------------------------------ #
# summary                                                             #
# ------------------------------------------------------------------ #

if(FAILS)
    foreach(f IN LISTS FAILS)
        message(STATUS "cli-e2e FAIL: ${f}")
    endforeach()
    message(FATAL_ERROR "cli-e2e: ${PASSES} passed, failures:\n${FAILS}")
endif()
message(STATUS "cli-e2e: all ${PASSES} checks passed")