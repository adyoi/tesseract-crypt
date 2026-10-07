# Key Rotation with Tesseract Crypt

Rotating keys is the process of re-encrypting existing encrypted files so that they can be decrypted with a **new recipient private key** (and, optionally, a new sender key). The payload and signatures remain unchanged; only the key material that wraps the data key is refreshed.

## Why Rotate?

- **Compromise recovery** – if you suspect an old recipient private key may have been exposed, rotate to a fresh key pair immediately.
- **Compliance** – many security policies require periodic re-encryption of stored credentials.
- **Key lifecycle** – replaces old keys as users leave a project or certificates expire.

## Prerequisites

- The old recipient **private key** (or the old passphrase for passphrase-protected files).
- The new recipient **public key** (generated with `tesseract-crypt keygen`).
- Optional: a new sender private key if you also want to rotate the signing identity.
- All files must be encrypted with the same old recipient (or sender) that you can open.

## Using `rotate_keys.py`

The provided helper `scripts/rotate_keys.py` drives the CLI’s `rekey` subcommand over a directory tree (both `*.enc` and `*.crypt` extensions are handled).

```bash
python3 scripts/rotate_keys.py \
    --old-key /path/to/old_sender.key \
    --new-recipient /path/to/new_recipient.pub \
    --sender-key /path/to/new_sender.key \
    --directory /data/secrets \
    --output-dir /data/secrets_new
```

- `--old-key` – the **old** sender/private key that can decrypt the existing files.
- `--new-recipient` – the new recipient public key that will be able to decrypt the re-encrypted files.
- `--sender-key` (optional) – if present, the output files will be signed with this new key; otherwise the original sender identity is preserved.
- `--directory` / `--output-dir` – source and destination directories. If `--output-dir` is omitted, files are overwritten in place (use with caution – keep backups).
- `--dry-run` – prints the commands that *would* run without executing them.

## Manual Rotation (single file)

You can rotate a single file with the CLI:

```bash
tesseract-crypt rekey \
    -k old_sender.key \
    -r new_recipient.pub \
    -i encrypted_file.enc \
    -o encrypted_file_rotated.enc \
    [-s new_sender.key] \
    [--no-sign]
```

- Use `--old-passphrase` instead of `-k` when the original file was encrypted with a passphrase.
- Use repeated `-r` flags to target multiple new recipients at once (format v2).

## Audit Trail & Verification

After rotating, verify a sample of files:

```bash
tesseract-crypt decrypt -k new_recipient.key -i encrypted_file_rotated.enc -o decrypted.txt
```

The decrypted output should match the original plaintext exactly. Optionally, run `tesseract-crypt verify` on the re-encrypted file to confirm the signature (if one was kept) is still valid.

## Best Practices

1. **Back up** the original files before rotating, especially when using in-place mode.
2. Rotate **in batches** (e.g. per directory or per project) rather than all at once, so a failure is easier to isolate.
3. **Revoke** access to the old key after rotation has been verified everywhere.
4. Run the script with `--dry-run` first to review the command list.
