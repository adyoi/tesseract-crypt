cmake_minimum_required(VERSION 3.16)

project(tesseract-crypt
    VERSION 1.0.2
    DESCRIPTION "Hybrid public-key string & file encryption (libsodium)"
    LANGUAGES C CXX)

# ------------------------------------------------------------------ #
# options                                                             #
# ------------------------------------------------------------------ #
option(TESS_BUILD_CLI "Build the tesseract-crypt command line tool" ON)
option(TESS_BUILD_TESTS "Build the test suite" ON)
option(TESS_SANITIZE "Enable AddressSanitizer + UBSan" OFF)
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
find_package(unofficial-sodium CONFIG QUIET)
if(TARGET unofficial-sodium::sodium)
    set(TESS_SODIUM_TARGET unofficial-sodium::sodium)
else()
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
    find_package(Sodium REQUIRED)
    set(TESS_SODIUM_TARGET Sodium::sodium)
endif()

# Detect a static libsodium so packaging can drop the runtime dependency
# (release tarballs/.deb link libsodium statically and are self-contained).
get_target_property(TESS_SODIUM_LOCATION ${TESS_SODIUM_TARGET} IMPORTED_LOCATION)
if(NOT TESS_SODIUM_LOCATION)
    get_target_property(TESS_SODIUM_LOCATION
        ${TESS_SODIUM_TARGET} IMPORTED_LOCATION_RELEASE)
endif()
if(TESS_SODIUM_LOCATION MATCHES "\\.a$")
    set(TESS_SODIUM_STATIC TRUE)
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

    set(TESS_TESTS roundtrip tamper armor keys file sign vectors multi)
    foreach(t ${TESS_TESTS})
        add_executable(test_${t} tests/test_${t}.c)
        target_link_libraries(test_${t} PRIVATE tesseract::crypt)
        target_include_directories(test_${t} PRIVATE src/core)
        add_test(NAME ${t} COMMAND test_${t})
    endforeach()

    # Known-answer tests read fixtures from the source tree.
    target_compile_definitions(test_vectors PRIVATE
        TESS_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")
endif()

# ------------------------------------------------------------------ #
# fuzzing (libFuzzer — Clang only, enabled with -DTESS_FUZZ=ON)       #
# ------------------------------------------------------------------ #
if(TESS_FUZZ)
    foreach(f inspect dearmor key_parse)
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

if(TESS_BUILD_CLI)
    install(TARGETS ${TESS_CLI_TARGET}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    # Bundle the libsodium runtime DLL next to the executable so the packaged
    # Windows ZIP runs on a clean machine. vcpkg exposes an UNKNOWN imported
    # target pointing at the import library (.lib), so the DLL is resolved from
    # the install prefix's bin/ directory instead.
    if(WIN32)
        set(_sodium_dlls "")
        if(VCPKG_INSTALLED_DIR AND VCPKG_TARGET_TRIPLET)
            file(GLOB _sodium_dlls
                "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/bin/*sodium*.dll")
        endif()
        if(NOT _sodium_dlls AND TESS_SODIUM_LOCATION MATCHES "\\.(lib|dll\\.a)$")
            get_filename_component(_sodium_dir "${TESS_SODIUM_LOCATION}" DIRECTORY)
            get_filename_component(_sodium_prefix "${_sodium_dir}" DIRECTORY)
            file(GLOB _sodium_dlls "${_sodium_prefix}/bin/*sodium*.dll")
        elseif(TESS_SODIUM_LOCATION MATCHES "\\.dll$")
            set(_sodium_dlls "${TESS_SODIUM_LOCATION}")
        endif()
        if(_sodium_dlls)
            install(FILES ${_sodium_dlls} DESTINATION ${CMAKE_INSTALL_BINDIR})
        endif()
    endif()
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
set(CPACK_PACKAGE_CONTACT "Tesseract Crypt maintainers")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "String & file encryption with public/private keys (X25519 hybrid + Ed25519 sign)")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")

# Artifact names carry the OS and CPU so multi-arch releases stay distinct,
# e.g. tesseract-crypt-1.0.1-Linux-aarch64.tar.gz, ...-Windows-x64.zip.
# CI overrides TESS_PACKAGE_ARCH (x64, x86, arm64, x86_64, i686, aarch64,
# universal2, ...); the fallback below is only a best guess for local runs.
if(WIN32)
    set(TESS_OS_NAME "Windows")
elseif(APPLE)
    set(TESS_OS_NAME "macOS")
else()
    set(TESS_OS_NAME "Linux")
endif()

if(NOT TESS_PACKAGE_ARCH)
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(TESS_PACKAGE_ARCH "i686")
    else()
        set(TESS_PACKAGE_ARCH "x86_64")
    endif()
endif()

if(NOT TESS_PACKAGE_ARCH)
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(TESS_PACKAGE_ARCH "i686")
    else()
        set(TESS_PACKAGE_ARCH "x86_64")
    endif()
endif()

# Debian architecture name for the .deb metadata and filename.  CPack would
# otherwise derive it from the host (always amd64 on the x86_64 build hosts,
# even for an -m32 build), collapsing x86_64 and i686 onto the same file name.
if(TESS_PACKAGE_ARCH STREQUAL "x86_64" OR TESS_PACKAGE_ARCH STREQUAL "amd64")
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
elseif(TESS_PACKAGE_ARCH STREQUAL "i686" OR TESS_PACKAGE_ARCH STREQUAL "i386" OR
       TESS_PACKAGE_ARCH STREQUAL "x86")
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "i386")
elseif(TESS_PACKAGE_ARCH STREQUAL "aarch64" OR TESS_PACKAGE_ARCH STREQUAL "arm64")
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "arm64")
endif()

set(CPACK_PACKAGE_FILE_NAME
    "tesseract-crypt-${PROJECT_VERSION}-${TESS_OS_NAME}-${TESS_PACKAGE_ARCH}")

if(WIN32)
    set(CPACK_GENERATOR "ZIP")
elseif(APPLE)
    set(CPACK_GENERATOR "TGZ")
else()
    set(CPACK_GENERATOR "TGZ;DEB")
    set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
    # Static libsodium needs no runtime package; a shared one does.
    if(TESS_SODIUM_STATIC)
        set(CPACK_DEBIAN_PACKAGE_DEPENDS "")
    else()
        set(CPACK_DEBIAN_PACKAGE_DEPENDS "libsodium23")
    endif()
    set(CPACK_DEBIAN_FILE_NAME
        "tesseract-crypt_${PROJECT_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}.deb")
endif()

include(CPack)
