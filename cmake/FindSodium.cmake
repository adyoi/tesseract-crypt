# FindSodium.cmake — fallback finder for libsodium when no config package
# (e.g. distro packages: libsodium-dev, homebrew, manual install).
#
# Defines the imported target Sodium::sodium and sets SODIUM_FOUND.

# Search standard locations for sodium.h
find_path(SODIUM_INCLUDE_DIR
    NAMES sodium.h
    PATHS
        /usr/include
        /usr/local/include
        /opt/homebrew/include
        /opt/local/include
    PATH_SUFFIXES sodium)

# Search standard locations for libsodium
find_library(SODIUM_LIBRARY
    NAMES sodium libsodium
    PATHS
        /usr/lib
        /usr/lib/x86_64-linux-gnu
        /usr/lib/aarch64-linux-gnu
        /usr/local/lib
        /opt/homebrew/lib
        /opt/local/lib)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sodium
    REQUIRED_VARS SODIUM_LIBRARY SODIUM_INCLUDE_DIR
    FAIL_MESSAGE "libsodium not found. Install libsodium-dev (Debian/Ubuntu), libsodium (Arch), libsodium-devel (Fedora/RHEL), or libsodium via homebrew/macports.")

if(Sodium_FOUND AND NOT TARGET Sodium::sodium)
    add_library(Sodium::sodium UNKNOWN IMPORTED)
    set_target_properties(Sodium::sodium PROPERTIES
        IMPORTED_LOCATION "${SODIUM_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}")
endif()

mark_as_advanced(SODIUM_INCLUDE_DIR SODIUM_LIBRARY)
