---
name: Bug report
description: Laporkan kerusakan atau perilaku yang tak terduga
title: "[Bug] "
labels: ["bug"]
body:
  - type: textarea
    id: description
    attributes:
      label: Deskripsi
      description: Apa yang terjadi / apa yang seharusnya terjadi?
    validations:
      required: true
  - type: textarea
    id: reproduce
    attributes:
      label: Langkah reproduksi
      description: Perintah CLI atau potongan kode C/C++ yang memicu masalah.
      placeholder: |
        tesseract-crypt keygen -o alice --passphrase
        tesseract-crypt encrypt ...
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: Perilaku yang diharapkan
    validations:
      required: true
  - type: input
    id: version
    attributes:
      label: Versi
      description: Output `tesseract-crypt version`
    validations:
      required: true
  - type: dropdown
    id: platform
    attributes:
      label: Platform
      description: Di mana masalah terjadi?
      options:
        - Linux (x86_64)
        - Linux (aarch64)
        - Windows
        - macOS
        - BSD
        - Lainnya (jelaskan di kolom tambahan)
    validations:
      required: true
  - type: textarea
    id: logs
    attributes:
      label: Log / keluaran error
      description: Tempel keluaran lengkap dari terminal.
      render: shell
  - type: checkboxes
    id: security
    attributes:
      label: Kerahasiaan
      options:
        - label: Saya tidak menyertakan kunci privat, kata sandi, atau data sensitif di laporan ini.
          required: true
  - type: textarea
    id: context
    attributes:
      label: Konteks tambahan
      description: Variabel lingkungan, cara build (vcpkg/distro), dsb.