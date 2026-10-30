import os
import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC_PREFIX = b"STEGO_SIG_v1:"

class EncryptionEngine:
    """
    AES-256-CBC Encryption Engine with PBKDF2 Key Derivation 
    and SHA-256 payload integrity verification.
    """

    @staticmethod
    def derive_key(passphrase: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        return kdf.derive(passphrase.encode('utf-8'))

    @classmethod
    def encrypt_payload(cls, secret_text: str, passphrase: str) -> bytes:
        if not secret_text:
            raise ValueError("Secret message cannot be empty.")
        if not passphrase:
            raise ValueError("Encryption key cannot be empty.")

        # Compute SHA-256 checksum of raw secret for integrity validation
        checksum = hashlib.sha256(secret_text.encode('utf-8')).digest()[:8]
        raw_payload = MAGIC_PREFIX + checksum + secret_text.encode('utf-8')

        # Pad payload to 16-byte boundary using PKCS7
        padder = padding.PKCS7(128).padder()
        padded_payload = padder.update(raw_payload) + padder.finalize()

        # Generate salt & IV
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = cls.derive_key(passphrase, salt)

        # AES-CBC Encryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_payload) + encryptor.finalize()

        # Concatenate salt (16 bytes) + iv (16 bytes) + ciphertext
        return salt + iv + ciphertext

    @classmethod
    def decrypt_payload(cls, payload_bytes: bytes, passphrase: str) -> str:
        if len(payload_bytes) < 32:
            raise ValueError("Corrupted or invalid stego payload header.")
        if not passphrase:
            raise ValueError("Decryption key is required.")

        salt = payload_bytes[:16]
        iv = payload_bytes[16:32]
        ciphertext = payload_bytes[32:]

        if not ciphertext or len(ciphertext) % 16 != 0:
            raise ValueError("Invalid payload length or corrupted data.")

        key = cls.derive_key(passphrase, salt)

        try:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_payload = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()
            raw_payload = unpadder.update(padded_payload) + unpadder.finalize()
        except Exception:
            raise ValueError("Incorrect encryption key or corrupted data payload.")

        if not raw_payload.startswith(MAGIC_PREFIX):
            raise ValueError("Decryption key invalid or stego payload signature missing.")

        content = raw_payload[len(MAGIC_PREFIX):]
        if len(content) < 8:
            raise ValueError("Corrupted payload structure.")

        checksum = content[:8]
        secret_bytes = content[8:]

        expected_checksum = hashlib.sha256(secret_bytes).digest()[:8]
        if checksum != expected_checksum:
            raise ValueError("Payload checksum verification failed. Key may be incorrect.")

        return secret_bytes.decode('utf-8', errors='replace')


class VaultCipher:
    """Fernet helper for encrypting vault passphrases at rest."""

    _fernet = None

    @classmethod
    def init(cls, secret: str) -> None:
        digest = hashlib.sha256(secret.encode("utf-8")).digest()
        cls._fernet = Fernet(base64.urlsafe_b64encode(digest))

    @classmethod
    def encrypt(cls, plaintext: str) -> str:
        if cls._fernet is None:
            raise RuntimeError("VaultCipher is not initialized.")
        return cls._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    @classmethod
    def decrypt(cls, token: str) -> str:
        if cls._fernet is None:
            raise RuntimeError("VaultCipher is not initialized.")
        if not token:
            return ""
        try:
            return cls._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except (InvalidToken, ValueError):
            # Legacy rows stored in plaintext before vault encryption shipped.
            return token

if __name__ == "__main__":
    # Test encryption & decryption
    secret = "Top Secret StegoShield AI Message 123!"
    key = "CyberKey2026$"
    encrypted = EncryptionEngine.encrypt_payload(secret, key)
    print("Encrypted payload len:", len(encrypted))
    decrypted = EncryptionEngine.decrypt_payload(encrypted, key)
    print("Decrypted message:", decrypted)
    assert secret == decrypted, "Encryption test failed!"
    print("Encryption test passed successfully!")
