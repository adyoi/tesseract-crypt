cmake_minimum_required(VERSION 3.16)

project(tesseract-crypt
    VERSION 0.1.0
    DESCRIPTION "Hybrid public-key string & file encryption (libsodium)"
    LANGUAGES C CXX)

# ------------------------------------------------------------------ #
# options                                                             #
# ------------------------------------------------------------------ #
option(TESS_BUILD_CLI "Build the tesseract-crypt command line tool" ON)
option(TESS_BUILD_TESTS "Build the test suite" ON)
option(TESS_SANITIZE "Enable AddressSanitizer + UBSan" OFF)
option(TESS_COVERAGE "Enable code coverage instrumentation (gcov/lcov)" OFF)
option(TESS_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
option(TESS_FUZZ "Build libFuzzer harnesses (Clang only)" OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ------------------------------------------------------------------ #
# libsodium                                                           #
# ------------------------------------------------------------------ #
# Try the unofficial-sodium config package first (provided by vcpkg on Windows).
# If not found or broken, fall back to the project's FindSodium.cmake which
# works with system packages (libsodium-dev, homebrew, vcpkg without config, etc.).
find_package(unofficial-sodium CONFIG QUIET)
if(TARGET unofficial-sodium::sodium)
    # Validate that the imported target has a valid location for the
    # current build configuration (handles both single and multi-config).
    get_target_property(_loc unofficial-sodium::sodium IMPORTED_LOCATION)
    if(NOT _loc)
        # Multi-config: try per-config property
        string(TOUPPER "${CMAKE_BUILD_TYPE}" _cfg)
        get_target_property(_loc unofficial-sodium::sodium "IMPORTED_LOCATION_${_cfg}")
    endif()
    if(_loc AND EXISTS "${_loc}")
        set(TESS_SODIUM_TARGET unofficial-sodium::sodium)
    else()
        message(WARNING "unofficial-sodium config package found but target location invalid; falling back to FindSodium.cmake")
        set(_fallback_sodium TRUE)
    endif()
else()
    set(_fallback_sodium TRUE)
endif()

if(_fallback_sodium)
    # Fallback: use project's FindSodium.cmake (works everywhere)
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
    find_package(Sodium REQUIRED)
    set(TESS_SODIUM_TARGET Sodium::sodium)
endif()

# ------------------------------------------------------------------ #
# warnings / sanitizers                                               #
# ------------------------------------------------------------------ #
# add_compile_options(...) — silence MSVC CRT deprecation (fopen etc.)
if(MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(TESS_WARNINGS_AS_ERRORS)
        add_compile_options(-Werror)
    endif()
    if(TESS_SANITIZE)
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()
    if(TESS_COVERAGE)
        add_compile_options(--coverage -O0 -g)
        add_link_options(--coverage)
    endif()
elseif(MSVC)
    add_compile_options(/W4)
    if(TESS_WARNINGS_AS_ERRORS)
        add_compile_options(/WX)
    endif()
endif()

# Fuzzing: instrument the whole build (library + harness) for coverage and
# memory safety; the harness executables link the libFuzzer runtime on top
# (see the "fuzzing" section below and fuzz/*.c).
if(TESS_FUZZ)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "TESS_FUZZ requires Clang — configure with CC=clang")
    endif()
    if(TESS_SANITIZE)
        message(FATAL_ERROR "TESS_FUZZ already enables ASan+UBSan; drop TESS_SANITIZE")
    endif()
    add_compile_options(-fsanitize=fuzzer-no-link,address,undefined
                        -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

# ------------------------------------------------------------------ #
# library                                                             #
# ------------------------------------------------------------------ #
add_library(tesseract_crypt
    src/core/tess_status.c
    src/core/tess_util.c
    src/core/tess_header.c
    src/core/tess_keys.c
    src/core/tess_sign.c
    src/core/tess_seal.c
    src/core/tess_rekey.c
)
add_library(tesseract::crypt ALIAS tesseract_crypt)

target_include_directories(tesseract_crypt
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/core)

target_link_libraries(tesseract_crypt PUBLIC ${TESS_SODIUM_TARGET})

set_target_properties(tesseract_crypt PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME tesseract_crypt
    EXPORT_NAME crypt
    POSITION_INDEPENDENT_CODE ON)

# ------------------------------------------------------------------ #
# CLI                                                                 #
# ------------------------------------------------------------------ #
if(TESS_BUILD_CLI)
    set(TESS_CLI_TARGET tesseract_crypt_cli)
    add_executable(${TESS_CLI_TARGET} src/cli/main.cpp)
    # Canonical binary name is 'tesseract-crypt'; 'tscrypt' is installed
    # alongside it as an alias (see below).
    set_target_properties(${TESS_CLI_TARGET} PROPERTIES
        OUTPUT_NAME tesseract-crypt)
    target_link_libraries(${TESS_CLI_TARGET} PRIVATE tesseract::crypt)
    if(NOT MSVC)
        target_compile_options(${TESS_CLI_TARGET} PRIVATE -Wall -Wextra)
    endif()

    if(WIN32)
        set(TESS_CLI_ALIAS "tscrypt.exe")
    else()
        set(TESS_CLI_ALIAS "tscrypt")
    endif()

    # Build tree: drop a 'tscrypt' copy next to 'tesseract-crypt'.
    add_custom_command(TARGET ${TESS_CLI_TARGET} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:${TESS_CLI_TARGET}>
            $<TARGET_FILE_DIR:${TESS_CLI_TARGET}>/${TESS_CLI_ALIAS}
        COMMENT "Creating '${TESS_CLI_ALIAS}' alias for tesseract-crypt")
endif()

# ------------------------------------------------------------------ #
# tests                                                               #
# ------------------------------------------------------------------ #
if(TESS_BUILD_TESTS)
    enable_testing()

    set(TESS_TESTS roundtrip tamper armor keys file sign vectors multi rekey harden)
    foreach(t ${TESS_TESTS})
        add_executable(test_${t} tests/test_${t}.c)
        target_link_libraries(test_${t} PRIVATE tesseract::crypt)
        target_include_directories(test_${t} PRIVATE src/core)
        add_test(NAME ${t} COMMAND test_${t})
    endforeach()

    # Known-answer tests read fixtures from the source tree.
    target_compile_definitions(test_vectors PRIVATE
        TESS_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")

    # CLI end-to-end regression (exit codes, stdin/stdout binary pipes).
    if(TESS_BUILD_CLI)
        add_test(NAME cli
            COMMAND ${CMAKE_COMMAND}
                -DTESS_CLI_EXE=$<TARGET_FILE:${TESS_CLI_TARGET}>
                -DWORK_DIR=${CMAKE_CURRENT_BINARY_DIR}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_test.cmake)
    endif()
endif()

# ------------------------------------------------------------------ #
# fuzzing (libFuzzer — Clang only, enabled with -DTESS_FUZZ=ON)       #
# ------------------------------------------------------------------ #
if(TESS_FUZZ)
    foreach(f inspect dearmor key_parse open)
        add_executable(fuzz_${f} fuzz/fuzz_${f}.c)
        target_link_libraries(fuzz_${f} PRIVATE tesseract::crypt)
        target_link_options(fuzz_${f} PRIVATE -fsanitize=fuzzer)
    endforeach()
endif()

# ------------------------------------------------------------------ #
# install                                                             #
# ------------------------------------------------------------------ #
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS tesseract_crypt
    EXPORT tesseractTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(DIRECTORY include/tesseract
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# FindSodium.cmake is what resolves libsodium on distro-style installs
# (plain library, no config package); ship it with the config so that
# find_package(tesseract CONFIG) -> find_dependency(Sodium) works.
install(FILES cmake/FindSodium.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tesseract)

if(TESS_BUILD_CLI)
    install(TARGETS ${TESS_CLI_TARGET}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    if(UNIX)
        # Alias 'tscrypt' -> 'tesseract-crypt' as a symlink (DESTDIR-aware).
        install(CODE "
            set(_bin \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}\")
            execute_process(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink
                \"tesseract-crypt\" \"\${_bin}/${TESS_CLI_ALIAS}\")
        ")
    else()
        # Windows: no reliable symlinks, install a second copy.
        install(PROGRAMS $<TARGET_FILE:${TESS_CLI_TARGET}>
            DESTINATION ${CMAKE_INSTALL_BINDIR}
            RENAME ${TESS_CLI_ALIAS})
    endif()
    install(FILES man/tesseract-crypt.1
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/man/tscrypt.1")
        install(FILES man/tscrypt.1
            DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
    endif()
endif()

install(EXPORT tesseractTargets
    FILE tesseractTargets.cmake
    NAMESPACE tesseract::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tesseract)

configure_package_config_file(
    cmake/tesseract-config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/tesseract-config.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tesseract)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/tesseract-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/tesseract-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/tesseract-config-version.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tesseract)

# ------------------------------------------------------------------ #
# packaging                                                           #
# ------------------------------------------------------------------ #
set(CPACK_PACKAGE_NAME "tesseract-crypt")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_HOMEPAGE_URL
    "https://adyoi.github.io/tesseract-crypt/")
set(CPACK_PACKAGE_CONTACT "Tesseract Crypt maintainers")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "String & file encryption with public/private keys (X25519 hybrid + Ed25519 sign)")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")

if(WIN32)
    set(CPACK_GENERATOR "ZIP")
elseif(APPLE)
    set(CPACK_GENERATOR "TGZ")
else()
    set(CPACK_GENERATOR "TGZ;DEB")
    set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Tesseract Crypt maintainers")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libsodium23")
    # Derive the dependency list from the linked libraries instead of
    # hand-maintaining it (requires dpkg-shlibdeps at package time).
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
    set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
    # RPM is opt-in: only selected when rpmbuild is actually available.
    find_program(TESS_RPMBUILD_EXECUTABLE rpmbuild)
    if(TESS_RPMBUILD_EXECUTABLE)
        list(APPEND CPACK_GENERATOR "RPM")
        set(CPACK_RPM_PACKAGE_LICENSE "MIT")
        set(CPACK_RPM_PACKAGE_GROUP "Applications/System")
        set(CPACK_RPM_PACKAGE_REQUIRES "libsodium >= 1.0.18")
    endif()
endif()

include(CPack)
