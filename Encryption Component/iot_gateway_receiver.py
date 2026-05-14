do this when get the new terminal:

cd iomt_gateway
source venv/bin/activate
python iot_gateway_receiver.py

pi code:
***********************************************************
import socket
import json
import base64
import time
import hmac
import hashlib
from datetime import datetime

import psutil
from Crypto.Cipher import AES


UDP_IP = "0.0.0.0"
UDP_PORT = 5005

LOG_FILE = "iot_encryption_gateway_log.jsonl"
CLEAN_DATA_FILE = "decrypted_iomt_payloads.jsonl"


# Same AES key used in ESP32-2 code
AES_KEY = bytes([
    0x10, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC,
    0xDD, 0xEE, 0xF0, 0x12
])


# Same HMAC key used in ESP32-2 code
HMAC_KEY = bytes([
    0x91, 0x82, 0x73, 0x64,
    0x55, 0x46, 0x37, 0x28,
    0x19, 0x2A, 0x3B, 0x4C,
    0x5D, 0x6E, 0x7F, 0x80,
    0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC
])


def b64_to_bytes(value):
    return base64.b64decode(value.encode())


def b64_to_string(value):
    return base64.b64decode(value.encode()).decode(errors="replace")


def calculate_hmac(message):
    digest = hmac.new(
        HMAC_KEY,
        message.encode(),
        hashlib.sha256
    ).digest()

    return base64.b64encode(digest).decode()


def decrypt_aes_gcm(packet):
    nonce = b64_to_bytes(packet["iv"])
    ciphertext = b64_to_bytes(packet["ciphertext"])
    tag = b64_to_bytes(packet["tag"])

    cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext.decode(errors="replace")


def decrypt_aes_ctr_hmac(packet):
    iv_b64 = packet["iv"]
    ciphertext_b64 = packet["ciphertext"]
    received_hmac = packet["hmac"]

    hmac_message = iv_b64 + ciphertext_b64
    calculated_hmac = calculate_hmac(hmac_message)

    if not hmac.compare_digest(received_hmac, calculated_hmac):
        raise ValueError("HMAC verification failed")

    iv = b64_to_bytes(iv_b64)
    ciphertext = b64_to_bytes(ciphertext_b64)

    initial_value = int.from_bytes(iv, byteorder="big")

    cipher = AES.new(
        AES_KEY,
        AES.MODE_CTR,
        nonce=b"",
        initial_value=initial_value
    )

    plaintext = cipher.decrypt(ciphertext)

    return plaintext.decode(errors="replace")


def verify_hmac_only(packet):
    payload_b64 = packet["payload"]
    received_hmac = packet["hmac"]

    calculated_hmac = calculate_hmac(payload_b64)

    if not hmac.compare_digest(received_hmac, calculated_hmac):
        raise ValueError("HMAC verification failed")

    return b64_to_string(payload_b64)


def write_jsonl(filename, record):
    with open(filename, "a", encoding="utf-8") as file:
        file.write(json.dumps(record) + "\n")


def process_packet(packet, sender_ip):
    decrypt_start = time.perf_counter()

    algorithm = packet.get("algorithm", "UNKNOWN")
    status = "FAILED"
    action = "REJECT"
    plaintext = None
    error = None

    try:
        if algorithm == "AES-GCM":
            plaintext = decrypt_aes_gcm(packet)

        elif algorithm == "AES-CTR-HMAC":
            plaintext = decrypt_aes_ctr_hmac(packet)

        elif algorithm == "HMAC-ONLY":
            plaintext = verify_hmac_only(packet)

        else:
            raise ValueError("Unsupported algorithm: " + algorithm)

        status = "VERIFIED"
        action = "FORWARD"

    except Exception as e:
        error = str(e)

    decrypt_end = time.perf_counter()
    decrypt_us = int((decrypt_end - decrypt_start) * 1_000_000)

    cpu_usage = psutil.cpu_percent(interval=None)
    ram_usage = psutil.virtual_memory().percent

    log_record = {
        "gateway_time": datetime.now().isoformat(),
        "sender_ip": sender_ip,
        "device_id": packet.get("device_id"),
        "source_node": packet.get("source_node"),
        "seq": packet.get("seq"),
        "sensitivity": packet.get("sensitivity"),
        "algorithm": algorithm,
        "packet_size": packet.get("packet_size"),
        "classify_us": packet.get("classify_us"),
        "encrypt_us": packet.get("encrypt_us"),
        "esp_total_us": packet.get("total_us"),
        "decrypt_us": decrypt_us,
        "esp_free_heap": packet.get("free_heap"),
        "pi_cpu_percent": cpu_usage,
        "pi_ram_percent": ram_usage,
        "verification_status": status,
        "action": action,
        "error": error
    }

    write_jsonl(LOG_FILE, log_record)

    if plaintext is not None:
        try:
            clean_payload = json.loads(plaintext)
        except Exception:
            clean_payload = plaintext

        clean_record = {
            "gateway_time": datetime.now().isoformat(),
            "seq": packet.get("seq"),
            "sensitivity": packet.get("sensitivity"),
            "algorithm": algorithm,
            "payload": clean_payload
        }

        write_jsonl(CLEAN_DATA_FILE, clean_record)

    print()
    print("==================================================")
    print("ENCRYPTED PACKET RECEIVED FROM ESP32-2")
    print("==================================================")
    print("Sender IP              :", sender_ip)
    print("Sequence No            :", packet.get("seq"))
    print("Sensitivity Level      :", packet.get("sensitivity"))
    print("Selected Algorithm     :", algorithm)
    print("ESP Classification us  :", packet.get("classify_us"))
    print("ESP Encryption us      :", packet.get("encrypt_us"))
    print("ESP Total Process us   :", packet.get("total_us"))
    print("ESP Free Heap          :", packet.get("free_heap"))
    print("Pi Decryption us       :", decrypt_us)
    print("Pi CPU Usage %         :", cpu_usage)
    print("Pi RAM Usage %         :", ram_usage)
    print("Verification Status    :", status)
    print("Action                 :", action)

    if plaintext is not None:
        print()
        print("DECRYPTED SENSOR PAYLOAD")
        print("--------------------------------------------------")
        print(plaintext)

    if error is not None:
        print()
        print("ERROR")
        print("--------------------------------------------------")
        print(error)

    print("==================================================")


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    print("==================================================")
    print("Raspberry Pi IoMT Secure Gateway Receiver Started")
    print("==================================================")
    print("AES-128 key loaded")
    print("HMAC-SHA256 key loaded")
    print("Listening IP   :", UDP_IP)
    print("Listening Port :", UDP_PORT)
    print("Log File       :", LOG_FILE)
    print("Clean Data File:", CLEAN_DATA_FILE)
    print("Waiting for encrypted packets from ESP32-2...")
    print("==================================================")

    while True:
        data, addr = sock.recvfrom(4096)
        sender_ip = addr[0]

        try:
            packet_text = data.decode()
            packet = json.loads(packet_text)

            process_packet(packet, sender_ip)

        except Exception as e:
            failed_record = {
                "gateway_time": datetime.now().isoformat(),
                "sender_ip": sender_ip,
                "verification_status": "FAILED",
                "action": "REJECT",
                "error": str(e),
                "raw_data": data.decode(errors="replace")
            }

            write_jsonl(LOG_FILE, failed_record)

            print()
            print("Invalid packet received")
            print("Error:", e)


if __name__ == "__main__":
    main()