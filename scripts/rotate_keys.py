#!/usr/bin/env python3
"""Key rotation utility for Tesseract Crypt.

This script helps rotate recipient keys on encrypted files by rekeying each
*.enc / *.crypt file in a directory to a new recipient public key (and,
optionally, a new sender secret key). It wraps the CLI's `rekey` subcommand.

Usage:
    python3 rotate_keys.py \
        --old-key /path/to/old_sender.key \
        --new-recipient /path/to/new_recipient.pub \
        --directory /data/secrets \
        [--sender-key /path/to/new_sender.key] \
        [--output-dir /data/secrets_new]
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

CLI = "tesseract-crypt"


def run_cmd(cmd_args, dry_run=False):
    print(" ".join(cmd_args))
    if dry_run:
        return 0
    proc = subprocess.run(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        print(f"ERROR: {proc.stderr}", file=sys.stderr)
    return proc.returncode


def main():
    parser = argparse.ArgumentParser(description="Rotate recipient keys for Tesseract Crypt files.")
    parser.add_argument("--old-key", required=True, help="Path to the old sender private key.")
    parser.add_argument("--new-recipient", required=True, help="Path to the new recipient public key.")
    parser.add_argument("--sender-key", default=None, help="Path to the new sender private key.")
    parser.add_argument("--directory", required=True, help="Directory containing *.enc files.")
    parser.add_argument("--output-dir", default=None, help="Output directory (defaults to same directory).")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing.")
    args = parser.parse_args()

    in_dir = Path(args.directory).resolve()
    if not in_dir.is_dir():
        sys.exit(f"Directory not found: {in_dir}")
    out_dir = Path(args.output_dir).resolve() if args.output_dir else in_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    for path in in_dir.glob("**/*.enc"):
        rel = path.relative_to(in_dir)
        out_path = out_dir / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            CLI, "rekey",
            "-k", args.old_key,
            "-r", args.new_recipient,
            "-i", str(path),
            "-o", str(out_path),
        ]
        if args.sender_key:
            cmd.extend(["-s", args.sender_key])
        if run_cmd(cmd, dry_run=args.dry_run) != 0:
            sys.exit(f"Rotation failed for {path}")

    # Also handle *.crypt extensions
    for path in in_dir.glob("**/*.crypt"):
        rel = path.relative_to(in_dir)
        out_path = out_dir / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            CLI, "rekey",
            "-k", args.old_key,
            "-r", args.new_recipient,
            "-i", str(path),
            "-o", str(out_path),
        ]
        if args.sender_key:
            cmd.extend(["-s", args.sender_key])
        if run_cmd(cmd, dry_run=args.dry_run) != 0:
            sys.exit(f"Rotation failed for {path}")

    print("Rotation complete.")


if __name__ == "__main__":
    main()
