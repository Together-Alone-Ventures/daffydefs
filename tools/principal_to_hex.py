#!/usr/bin/env python3
import base64
import binascii
import sys


def fail(msg: str) -> None:
    print(msg, file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) != 2:
        fail("Usage: principal_to_hex.py <principal>")

    principal = sys.argv[1].strip()
    if not principal:
        fail("Error: principal argument is empty")

    normalized = principal.replace("-", "").upper()

    # Principal text uses base32 without padding; restore padding for decoder.
    pad_len = (-len(normalized)) % 8
    padded = normalized + ("=" * pad_len)

    try:
        decoded = base64.b32decode(padded, casefold=True)
    except (binascii.Error, ValueError) as e:
        fail(f"Error: failed to decode principal '{principal}': {e}")

    if len(decoded) < 5:
        fail(f"Error: decoded principal '{principal}' is too short")

    raw = decoded[4:]  # Strip 4-byte CRC32 prefix.
    print(raw.hex())


if __name__ == "__main__":
    main()
