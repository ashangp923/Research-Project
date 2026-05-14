#!/usr/bin/env python3
"""
Danuka Project - Cowrie Honeypot Log Encryption Script
Component: Local Edge Honeypot for Medical IoT Threat Intelligence

Purpose:
- Copy the latest Cowrie JSON log.
- Encrypt it using AES-GCM.
- Store the encrypted file locally for secure incident log storage.

Input:
- /home/cowrie/cowrie/var/log/cowrie/cowrie.json

Output:
- /home/pi/Desktop/cowrie_logs/normal/cowrie_latest.json
- /home/pi/Desktop/cowrie_logs/encrypted/cowrie_latest.json.enc
"""

import os
import json
import base64
import shutil
from datetime import datetime
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ---------------------------------------------------------------------------
# File paths used in the  honeypot implementation
# ---------------------------------------------------------------------------

SOURCE_LOG = Path("/home/cowrie/cowrie/var/log/cowrie/cowrie.json")

NORMAL_DIR = Path("/home/pi/Desktop/cowrie_logs/normal")
ENCRYPTED_DIR = Path("/home/pi/Desktop/cowrie_logs/encrypted")

NORMAL_COPY = NORMAL_DIR / "cowrie_latest.json"
ENCRYPTED_FILE = ENCRYPTED_DIR / "cowrie_latest.json.enc"

# AES-256 key file.
# Keep this file private. It is required for decryption.
KEY_FILE = Path("/home/pi/Desktop/cowrie_logs/encryption.key")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def create_directories():
    """Create required output directories if they do not exist."""
    NORMAL_DIR.mkdir(parents=True, exist_ok=True)
    ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)


def get_or_create_key():
    """
    Load AES key if it exists.
    Otherwise create a new 256-bit AES key and save it locally.
    """
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()

    key = get_random_bytes(32)  # 32 bytes = AES-256
    KEY_FILE.write_bytes(key)

    # Restrict key file permissions to owner only
    try:
        os.chmod(KEY_FILE, 0o600)
    except PermissionError:
        pass

    return key


def copy_latest_log():
    """Copy Cowrie JSON log into the normal evidence folder."""
    if not SOURCE_LOG.exists():
        raise FileNotFoundError(f"Source Cowrie log not found: {SOURCE_LOG}")

    shutil.copy2(SOURCE_LOG, NORMAL_COPY)
    return NORMAL_COPY


def encrypt_file(input_file, output_file, key):
    """
    Encrypt the input file using AES-GCM.
    AES-GCM provides confidentiality and integrity protection.
    """
    plaintext = input_file.read_bytes()

    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    encrypted_package = {
        "project": "Danuka",
        "component": "Local Edge Honeypot",
        "source_file": str(input_file),
        "encrypted_at_utc": datetime.utcnow().isoformat() + "Z",
        "algorithm": "AES-256-GCM",
        "nonce_b64": base64.b64encode(cipher.nonce).decode("utf-8"),
        "tag_b64": base64.b64encode(tag).decode("utf-8"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8")
    }

    output_file.write_text(json.dumps(encrypted_package, indent=4), encoding="utf-8")
    return output_file


def main():
    create_directories()
    key = get_or_create_key()

    copied_file = copy_latest_log()
    encrypted_file = encrypt_file(copied_file, ENCRYPTED_FILE, key)

    print("[OK] Cowrie log copied to:", copied_file)
    print("[OK] Cowrie log encrypted to:", encrypted_file)
    print("[INFO] Key file location:", KEY_FILE)


if __name__ == "__main__":
    main()
