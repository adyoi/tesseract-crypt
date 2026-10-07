Name:           tesseract-crypt
Version:        0.1.0
Release:        1%{?dist}
Summary:        String & file encryption with public/private keys (X25519 hybrid + Ed25519 sign)
License:        MIT
URL:            https://github.com/adyoi/tesseract-crypt
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  cmake >= 3.16
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  libsodium-devel
Requires:       libsodium

%description
Tesseract Crypt is a hybrid public-key encryption tool for strings and files,
combining ephemeral X25519 (forward secrecy) with static DH identity binding,
BLAKE2b KDF, and XChaCha20-Poly1305 AEAD. It supports sign-then-encrypt with
Ed25519, chunked streaming, PEM-like armor, passphrase mode (Argon2id),
and multi-recipient format v2.

%prep
%autosetup -n %{name}-%{version}

%build
%cmake -DCMAKE_BUILD_TYPE=Release -DTESS_WARNINGS_AS_ERRORS=ON
%cmake_build

%install
%cmake_install

%check
%ctest

%files
%license LICENSE
%doc README.md CHANGELOG.md SECURITY.md
%{_bindir}/tesseract-crypt
%{_bindir}/tscrypt
%{_mandir}/man1/tesseract-crypt.1*
%{_mandir}/man1/tscrypt.1*
%{_includedir}/tesseract/tesseract.h
%{_includedir}/tesseract/tesseract.hpp
%{_libdir}/libtesseract_crypt.so
%{_libdir}/libtesseract_crypt.so.%{version}
%{_libdir}/libtesseract_crypt.so.%{version_major}
%{_libdir}/cmake/tesseract/tesseractTargets.cmake
%{_libdir}/cmake/tesseract/tesseractTargets-%{_cmake_build_type}.cmake
%{_libdir}/cmake/tesseract/tesseract-config.cmake
%{_libdir}/cmake/tesseract/tesseract-config-version.cmake

%changelog
* Wed Oct 07 2026 Tesseract Crypt maintainers <maintainers@tesseract-crypt.org> - 0.1.0-1
- Initial package.
