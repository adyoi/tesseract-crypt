# FindSodium.cmake — fallback finder for libsodium when no config package
# (e.g. distro packages: libsass / libsodium-dev).
#
# Defines the imported target Sodium::sodium and sets SODIUM_FOUND.

find_path(SODIUM_INCLUDE_DIR
    NAMES sodium.h
    PATH_SUFFIXES sodium)

find_library(SODIUM_LIBRARY
    NAMES sodium libsodium)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sodium
    REQUIRED_VARS SODIUM_LIBRARY SODIUM_INCLUDE_DIR)

if(Sodium_FOUND AND NOT TARGET Sodium::sodium)
    add_library(Sodium::sodium UNKNOWN IMPORTED)
    set_target_properties(Sodium::sodium PROPERTIES
        IMPORTED_LOCATION "${SODIUM_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}")
endif()

mark_as_advanced(SODIUM_INCLUDE_DIR SODIUM_LIBRARY)
