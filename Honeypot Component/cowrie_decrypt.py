#!/usr/bin/env python3
"""
Danuka Project - Cowrie Honeypot Log Decryption Script
Component: Local Edge Honeypot for Medical IoT Threat Intelligence

Purpose:
- Decrypt the encrypted Cowrie JSON log created by cowrie_encrypt.py.
- Verify integrity using AES-GCM authentication tag.
- Save decrypted output for analysis/demo.

Input:
- /home/pi/Desktop/cowrie_logs/encrypted/cowrie_latest.json.enc

Output:
- /home/pi/Desktop/cowrie_logs/decrypted/cowrie_latest_decrypted.json
"""

import json
import base64
from pathlib import Path
from Crypto.Cipher import AES


# ---------------------------------------------------------------------------
# File paths used in the honeypot implementation
# ---------------------------------------------------------------------------

ENCRYPTED_FILE = Path("/home/pi/Desktop/cowrie_logs/encrypted/cowrie_latest.json.enc")
DECRYPTED_DIR = Path("/home/pi/Desktop/cowrie_logs/decrypted")
DECRYPTED_FILE = DECRYPTED_DIR / "cowrie_latest_decrypted.json"

KEY_FILE = Path("/home/pi/Desktop/cowrie_logs/encryption.key")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def decrypt_file(encrypted_file, output_file, key):
    """Decrypt AES-GCM encrypted Cowrie log file."""
    if not encrypted_file.exists():
        raise FileNotFoundError(f"Encrypted file not found: {encrypted_file}")

    encrypted_package = json.loads(encrypted_file.read_text(encoding="utf-8"))

    nonce = base64.b64decode(encrypted_package["nonce_b64"])
    tag = base64.b64decode(encrypted_package["tag_b64"])
    ciphertext = base64.b64decode(encrypted_package["ciphertext_b64"])

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # decrypt_and_verify checks both confidentiality and integrity
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    output_file.write_bytes(plaintext)
    return output_file


def main():
    if not KEY_FILE.exists():
        raise FileNotFoundError(f"Key file not found: {KEY_FILE}")

    key = KEY_FILE.read_bytes()

    DECRYPTED_DIR.mkdir(parents=True, exist_ok=True)

    decrypted_file = decrypt_file(ENCRYPTED_FILE, DECRYPTED_FILE, key)

    print("[OK] Cowrie log decrypted to:", decrypted_file)


if __name__ == "__main__":
    main()
