---
name: Bug report
description: Report breakage or unexpected behavior
title: "[Bug] "
labels: ["bug"]
body:
  - type: textarea
    id: description
    attributes:
      label: Description
      description: What happened / what did you expect to happen?
    validations:
      required: true
  - type: textarea
    id: reproduce
    attributes:
      label: Steps to reproduce
      description: The CLI command or C/C++ snippet that triggers the problem.
      placeholder: |
        tesseract-crypt keygen -o alice --passphrase
        tesseract-crypt encrypt ...
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: Expected behavior
    validations:
      required: true
  - type: input
    id: version
    attributes:
      label: Version
      description: Output of `tesseract-crypt version`
    validations:
      required: true
  - type: dropdown
    id: platform
    attributes:
      label: Platform
      description: Where does the problem occur?
      options:
        - Linux (x86_64)
        - Linux (aarch64)
        - Windows
        - macOS
        - BSD
        - Other (describe below)
    validations:
      required: true
  - type: textarea
    id: logs
    attributes:
      label: Logs / error output
      description: Paste the full output from your terminal.
      render: shell
  - type: checkboxes
    id: security
    attributes:
      label: Confidentiality
      options:
        - label: I have not included private keys, passphrases, or sensitive data in this report.
          required: true
  - type: textarea
    id: context
    attributes:
      label: Additional context
      description: Environment variables, build method (vcpkg/distro), etc.