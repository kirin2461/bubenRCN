"""
Encryption module for Network Changer Pro v2.0.0
Supports: Ed25519, ChaCha20-Poly1305, AES-256-GCM, PBKDF2-SHA256
"""

import os
import json
import hashlib
import hmac
from typing import Tuple, Union
from datetime import datetime, timedelta

import nacl.utils
import nacl.secret
import nacl.pwhash
import nacl.bindings
from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import base64


class CryptoManager:
    """
    Cryptographic operations manager for Network Changer Pro
    
    Features:
    - Ed25519 digital signatures (256-bit elliptic curve)
    - ChaCha20-Poly1305 authenticated encryption (256-bit)
    - Curve25519 ECDH key exchange (Perfect Forward Secrecy)
    - AES-256-GCM for local storage (256-bit)
    - PBKDF2-SHA256 password hashing (100,000 iterations)
    """
    
    # Algorithm constants
    PBKDF2_ITERATIONS = 100_000  # OWASP recommendation
    SALT_LENGTH = 32  # 256-bit salt
    NONCE_LENGTH = 24  # 192-bit nonce (ChaCha20-Poly1305)
    AES_NONCE_LENGTH = 12  # 96-bit nonce (AES-GCM)
    TAG_LENGTH = 16  # 128-bit authentication tag
    
    def __init__(self):
        """Initialize cryptography manager"""
        self.backend = default_backend()
    
    # ============ Ed25519 Digital Signatures ============
    
    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """
        Generate Ed25519 keypair for digital signatures
        
        Returns:
            Tuple[signing_key_b64, verify_key_b64]
        """
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        
        return (
            base64.b64encode(bytes(signing_key)).decode(),
            base64.b64encode(bytes(verify_key)).decode()
        )
    
    @staticmethod
    def sign_message(message: Union[str, bytes], signing_key_b64: str) -> str:
        """
        Sign message with Ed25519 private key
        
        Args:
            message: Message to sign (str or bytes)
            signing_key_b64: Base64-encoded signing key
            
        Returns:
            Base64-encoded signature
        """
        if isinstance(message, str):
            message = message.encode()
        
        signing_key = SigningKey(base64.b64decode(signing_key_b64))
        signature = signing_key.sign(message).signature
        
        return base64.b64encode(signature).decode()
    
    @staticmethod
    def verify_signature(message: Union[str, bytes], signature_b64: str, verify_key_b64: str) -> bool:
        """
        Verify Ed25519 signature
        
        Args:
            message: Original message
            signature_b64: Base64-encoded signature
            verify_key_b64: Base64-encoded verify key
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            if isinstance(message, str):
                message = message.encode()
            
            verify_key = VerifyKey(base64.b64decode(verify_key_b64))
            verify_key.verify(message, base64.b64decode(signature_b64))
            return True
        except Exception:
            return False
    
    # ============ ChaCha20-Poly1305 Authenticated Encryption ============
    
    @staticmethod
    def generate_chacha20_key() -> str:
        """
        Generate random 256-bit key for ChaCha20-Poly1305
        
        Returns:
            Base64-encoded key
        """
        key = nacl.utils.random(32)  # 256-bit
        return base64.b64encode(key).decode()
    
    @staticmethod
    def encrypt_chacha20(
        plaintext: Union[str, bytes],
        key_b64: str,
        nonce_b64: str = None,
        aad: bytes = None
    ) -> dict:
        """
        Encrypt with ChaCha20-Poly1305
        
        Args:
            plaintext: Data to encrypt
            key_b64: Base64-encoded 256-bit key
            nonce_b64: Optional base64-encoded nonce (auto-generated if not provided)
            aad: Optional Additional Authenticated Data
            
        Returns:
            dict with 'ciphertext_b64', 'nonce_b64', 'tag_b64'
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        key = base64.b64decode(key_b64)
        cipher = ChaCha20Poly1305(key)
        
        if nonce_b64 is None:
            nonce = os.urandom(12)  # 96-bit nonce for ChaCha20Poly1305
            nonce_b64 = base64.b64encode(nonce).decode()
        else:
            nonce = base64.b64decode(nonce_b64)
        
        ciphertext = cipher.encrypt(nonce, plaintext, aad)
        
        return {
            'ciphertext_b64': base64.b64encode(ciphertext).decode(),
            'nonce_b64': nonce_b64,
            'aad': aad.hex() if aad else None
        }
    
    @staticmethod
    def decrypt_chacha20(
        ciphertext_b64: str,
        key_b64: str,
        nonce_b64: str,
        aad: bytes = None
    ) -> bytes:
        """
        Decrypt ChaCha20-Poly1305 ciphertext
        
        Args:
            ciphertext_b64: Base64-encoded ciphertext
            key_b64: Base64-encoded key
            nonce_b64: Base64-encoded nonce
            aad: Optional AAD
            
        Returns:
            Decrypted plaintext (bytes)
        """
        key = base64.b64decode(key_b64)
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        
        cipher = ChaCha20Poly1305(key)
        plaintext = cipher.decrypt(nonce, ciphertext, aad)
        
        return plaintext
    
    # ============ Curve25519 ECDH Key Exchange ============
    
    @staticmethod
    def generate_ecdh_keypair() -> Tuple[str, str]:
        """
        Generate Curve25519 keypair for ECDH key exchange
        
        Returns:
            Tuple[private_key_b64, public_key_b64]
        """
        private_key = PrivateKey.generate()
        public_key = private_key.public_key
        
        return (
            base64.b64encode(bytes(private_key)).decode(),
            base64.b64encode(bytes(public_key)).decode()
        )
    
    @staticmethod
    def compute_shared_secret(private_key_b64: str, public_key_b64: str) -> str:
        """
        Compute shared secret via Curve25519 ECDH
        
        Args:
            private_key_b64: Our private key
            public_key_b64: Their public key
            
        Returns:
            Base64-encoded shared secret (256-bit)
        """
        private_key = PrivateKey(base64.b64decode(private_key_b64))
        public_key = PublicKey(base64.b64decode(public_key_b64))
        
        shared_secret = nacl.bindings.crypto_box_beforenm(
            public_key.encode(),
            private_key.encode()
        )
        
        return base64.b64encode(shared_secret).decode()
    
    # ============ AES-256-GCM for Local Storage ============
    
    @staticmethod
    def generate_aes_key() -> str:
        """
        Generate random 256-bit AES key
        
        Returns:
            Base64-encoded key
        """
        key = os.urandom(32)  # 256-bit
        return base64.b64encode(key).decode()
    
    @staticmethod
    def encrypt_aes_gcm(
        plaintext: Union[str, bytes],
        key_b64: str,
        aad: bytes = None
    ) -> dict:
        """
        Encrypt with AES-256-GCM
        
        Args:
            plaintext: Data to encrypt
            key_b64: Base64-encoded 256-bit key
            aad: Optional Additional Authenticated Data
            
        Returns:
            dict with 'ciphertext_b64', 'nonce_b64', 'tag_b64'
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        key = base64.b64decode(key_b64)
        cipher = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce
        
        ciphertext = cipher.encrypt(nonce, plaintext, aad)
        
        return {
            'ciphertext_b64': base64.b64encode(ciphertext[:-16]).decode(),  # Remove tag
            'tag_b64': base64.b64encode(ciphertext[-16:]).decode(),  # Last 16 bytes = tag
            'nonce_b64': base64.b64encode(nonce).decode()
        }
    
    @staticmethod
    def decrypt_aes_gcm(
        ciphertext_b64: str,
        tag_b64: str,
        key_b64: str,
        nonce_b64: str,
        aad: bytes = None
    ) -> bytes:
        """
        Decrypt AES-256-GCM ciphertext
        
        Args:
            ciphertext_b64: Base64-encoded ciphertext
            tag_b64: Base64-encoded authentication tag
            key_b64: Base64-encoded key
            nonce_b64: Base64-encoded nonce
            aad: Optional AAD
            
        Returns:
            Decrypted plaintext (bytes)
        """
        key = base64.b64decode(key_b64)
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        tag = base64.b64decode(tag_b64)
        
        cipher = AESGCM(key)
        plaintext = cipher.decrypt(nonce, ciphertext + tag, aad)
        
        return plaintext
    
    # ============ PBKDF2-SHA256 Password Hashing ============
    
    @staticmethod
    def derive_key_pbkdf2(
        password: Union[str, bytes],
        salt: bytes = None,
        iterations: int = PBKDF2_ITERATIONS
    ) -> dict:
        """
        Derive key from password using PBKDF2-SHA256
        
        Args:
            password: Master password
            salt: Optional salt (auto-generated if not provided)
            iterations: Number of iterations
            
        Returns:
            dict with 'key_b64', 'salt_b64', 'iterations'
        """
        if isinstance(password, str):
            password = password.encode()
        
        if salt is None:
            salt = os.urandom(32)  # 256-bit salt
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password)
        
        return {
            'key_b64': base64.b64encode(key).decode(),
            'salt_b64': base64.b64encode(salt).decode(),
            'iterations': iterations
        }
    
    # ============ HMAC-SHA256 Message Authentication ============
    
    @staticmethod
    def compute_hmac_sha256(message: Union[str, bytes], key_b64: str) -> str:
        """
        Compute HMAC-SHA256 for message authentication
        
        Args:
            message: Message to authenticate
            key_b64: Base64-encoded key
            
        Returns:
            Base64-encoded HMAC
        """
        if isinstance(message, str):
            message = message.encode()
        
        key = base64.b64decode(key_b64)
        h = crypto_hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message)
        
        return base64.b64encode(h.finalize()).decode()
    
    @staticmethod
    def verify_hmac_sha256(
        message: Union[str, bytes],
        hmac_b64: str,
        key_b64: str
    ) -> bool:
        """
        Verify HMAC-SHA256
        
        Args:
            message: Original message
            hmac_b64: Base64-encoded HMAC
            key_b64: Base64-encoded key
            
        Returns:
            True if HMAC is valid, False otherwise
        """
        try:
            computed_hmac = CryptoManager.compute_hmac_sha256(message, key_b64)
            return hmac.compare_digest(computed_hmac, hmac_b64)
        except Exception:
            return False
    
    # ============ Utility Functions ============
    
    @staticmethod
    def compute_sha256(data: Union[str, bytes]) -> str:
        """
        Compute SHA256 hash
        
        Args:
            data: Data to hash
            
        Returns:
            Hex-encoded hash
        """
        if isinstance(data, str):
            data = data.encode()
        
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def random_hex(length: int = 16) -> str:
        """
        Generate random hex string
        
        Args:
            length: Number of bytes (hex string will be 2x this length)
            
        Returns:
            Random hex string
        """
        return os.urandom(length).hex()


# Export main class
__all__ = ['CryptoManager']
