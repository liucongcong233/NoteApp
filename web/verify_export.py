"""Verify the HMAC of a grades CSV exported by NotesApp.

Usage:
    python verify_export.py grades.csv [SECRET]

The export appends its signature as the last line of the file, prefixed with
``#HMAC:``. This script re-hashes every preceding byte with the same secret and
compares it against the stored value. If the file was edited after export, the
check fails.
"""
import os
import sys
import hmac
import hashlib

SECRET = os.environ.get("EXPORT_HMAC_SECRET", "export-hmac-secret-2024")


def verify(path: str, secret: str) -> bool:
    with open(path, "rb") as fh:
        raw = fh.read()
    lines = raw.splitlines(keepends=True)
    if len(lines) < 2:
        return False
    sig_line = lines[-1]
    marker = b"#HMAC:"
    if not sig_line.startswith(marker):
        return False
    expected = sig_line[len(marker):].strip().decode()
    payload = b"".join(lines[:-1])
    computed = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, expected)


def main():
    if len(sys.argv) < 2:
        print("usage: python verify_export.py grades.csv [SECRET]")
        return 2
    path = sys.argv[1]
    secret = sys.argv[2] if len(sys.argv) > 2 else SECRET
    if not os.path.exists(path):
        print(f"error: file not found: {path}")
        return 2
    if verify(path, secret):
        print("OK: HMAC matches, file was not modified after export.")
        return 0
    print("FAILED: HMAC mismatch, the file was edited after export.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
