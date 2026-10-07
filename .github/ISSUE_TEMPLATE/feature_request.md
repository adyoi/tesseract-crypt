---
name: Feature request
description: Suggest a new feature or improvement
title: "[Feature] "
labels: ["enhancement"]
body:
  - type: textarea
    id: problem
    attributes:
      label: Problem / need
      description: What problem are you trying to solve?
    validations:
      required: true
  - type: textarea
    id: solution
    attributes:
      label: Proposed solution
      description: How should this feature work?
    validations:
      required: true
  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives considered
      description: Any other solutions or workarounds you have tried?
  - type: textarea
    id: crypto
    attributes:
      label: Cryptographic considerations
      description: |
        Format, key schedule, or algorithm changes must follow DEVELOPMENT.md
        and preserve: sign-then-encrypt, header-as-chunk AAD,
        forward secrecy, and memory hygiene. Describe the impact here.
  - type: checkboxes
    id: scope
    attributes:
      label: Scope
      options:
        - label: I am willing to help with the implementation (PR).