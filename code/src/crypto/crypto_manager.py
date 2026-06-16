"""
Crypto Manager - Handles digital signatures, key generation, and verification.

Supports Ed25519 (primary), RSA-PSS, and ECDSA (ECDSA-P256) algorithms.
Uses the `cryptography` library for all cryptographic operations.
"""

import os
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding, ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class KeyManager:
    """Manages key generation, loading, and storage."""

    DEFAULT_KEY_DIR = Path.home() / ".contract_signing_keys"

    @staticmethod
    def generate_ed25519_key_pair() -> tuple:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem

    @staticmethod
    def generate_rsa_pss_key_pair(key_size: int = 2048) -> tuple:
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem

    @staticmethod
    def generate_ecdsa_key_pair(curve=ec.SECP256R1()) -> tuple:
        private_key = ec.generate_private_key(curve, default_backend())
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem

    @staticmethod
    def save_key_to_file(key_pem: bytes, filepath: str) -> None:
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_bytes(key_pem)

    @staticmethod
    def load_private_key(filepath: str):
        key_data = Path(filepath).read_bytes()
        try:
            return serialization.load_pem_private_key(
                key_data, password=None, backend=default_backend()
            )
        except ValueError:
            raise ValueError(f"Invalid private key file: {filepath}")

    @staticmethod
    def load_public_key(filepath: str):
        key_data = Path(filepath).read_bytes()
        try:
            return serialization.load_pem_public_key(
                key_data, backend=default_backend()
            )
        except ValueError:
            raise ValueError(f"Invalid public key file: {filepath}")

    @staticmethod
    def load_key_from_bytes(key_pem: bytes):
        try:
            return serialization.load_pem_private_key(
                key_pem, password=None, backend=default_backend()
            )
        except ValueError:
            pass
        try:
            return serialization.load_pem_public_key(
                key_pem, backend=default_backend()
            )
        except ValueError:
            raise ValueError("Invalid key data")


class CryptoManager:
    """Handles digital signing and verification on contract parts."""

    def __init__(self, algorithm: str = "ed25519"):
        self.algorithm = algorithm.lower()
        if self.algorithm not in ("ed25519", "rsa-pss", "ecdsa"):
            raise ValueError(f"Unsupported algorithm: {algorithm}. Use 'ed25519', 'rsa-pss', or 'ecdsa'.")

    def sign_part(self, part_id: str, contract_id: str, sequence_number: int,
                  content: str, private_key) -> dict:
        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        data_to_sign = f"{contract_id}|{part_id}|{sequence_number}|{content_hash}".encode('utf-8')

        if self.algorithm == "ed25519":
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise TypeError("Expected Ed25519 private key")
            signature = private_key.sign(data_to_sign)
        elif self.algorithm == "ecdsa":
            if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                raise TypeError("Expected ECDSA private key")
            signature = private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))
        else:  # rsa-pss
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise TypeError("Expected RSA private key")
            signature = private_key.sign(
                data_to_sign,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )

        return {
            "part_id": part_id, "contract_id": contract_id,
            "sequence_number": sequence_number, "content": content,
            "hash": content_hash, "signature": signature.hex(),
            "algorithm": self.algorithm
        }

    def verify_part(self, part_data: dict, public_key) -> bool:
        content_hash = hashlib.sha256(part_data["content"].encode('utf-8')).hexdigest()
        if content_hash != part_data["hash"]:
            return False

        data_to_verify = (
            f"{part_data['contract_id']}|{part_data['part_id']}|"
            f"{part_data['sequence_number']}|{content_hash}"
        ).encode('utf-8')

        try:
            signature = bytes.fromhex(part_data["signature"])
        except (ValueError, TypeError):
            return False

        try:
            if self.algorithm == "ed25519":
                if not isinstance(public_key, ed25519.Ed25519PublicKey):
                    raise TypeError("Expected Ed25519 public key")
                public_key.verify(signature, data_to_verify)
            elif self.algorithm == "ecdsa":
                if not isinstance(public_key, ec.EllipticCurvePublicKey):
                    raise TypeError("Expected ECDSA public key")
                public_key.verify(signature, data_to_verify, ec.ECDSA(hashes.SHA256()))
            else:  # rsa-pss
                if not isinstance(public_key, rsa.RSAPublicKey):
                    raise TypeError("Expected RSA public key")
                public_key.verify(
                    signature, data_to_verify,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            return True
        except (InvalidSignature, TypeError, ValueError):
            return False

    def sign_manifest(self, manifest_data: str, private_key) -> bytes:
        data = manifest_data.encode('utf-8')
        if self.algorithm == "ed25519":
            return private_key.sign(data)
        elif self.algorithm == "ecdsa":
            return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        else:
            return private_key.sign(
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )

    def verify_manifest(self, manifest_data: str, signature: bytes, public_key) -> bool:
        data = manifest_data.encode('utf-8')
        try:
            if self.algorithm == "ed25519":
                public_key.verify(signature, data)
            elif self.algorithm == "ecdsa":
                public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            else:
                public_key.verify(
                    signature, data,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            return True
        except (InvalidSignature, TypeError, ValueError):
            return False