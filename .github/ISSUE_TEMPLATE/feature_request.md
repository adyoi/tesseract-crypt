---
name: Permintaan fitur
description: Usulkan fitur atau peningkatan baru
title: "[Fitur] "
labels: ["enhancement"]
body:
  - type: textarea
    id: problem
    attributes:
      label: Masalah / kebutuhan
      description: Masalah apa yang ingin Anda pecahkan?
    validations:
      required: true
  - type: textarea
    id: solution
    attributes:
      label: Solusi yang diusulkan
      description: Bagaimana fitur ini seharusnya bekerja?
    validations:
      required: true
  - type: textarea
    id: alternatives
    attributes:
      label: Alternatif yang dipertimbangkan
      description: Sudah mencoba solusi/workaround lain?
  - type: textarea
    id: crypto
    attributes:
      label: Pertimbangan kriptografi
      description: |
        Perubahan format, key schedule, atau algoritma harus mengikuti
        RENCANA.md dan mempertahankan: sign-then-encrypt, header-ke-chunk AAD,
        forward secrecy, dan kebersihan memori. Jelaskan dampaknya di sini.
  - type: checkboxes
    id: scope
    attributes:
      label: Cakupan
      options:
        - label: Saya bersedia membantu implementasi (PR).