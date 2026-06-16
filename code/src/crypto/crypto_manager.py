"""
Crypto Manager - Handles digital signatures, key generation, and verification.

Supports Ed25519 (primary) and RSA-PSS algorithms.
Uses the `cryptography` library for all cryptographic operations.
"""

import os
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class KeyManager:
    """Manages key generation, loading, and storage."""

    DEFAULT_KEY_DIR = Path.home() / ".contract_signing_keys"

    @staticmethod
    def generate_ed25519_key_pair() -> tuple:
        """
        Generate an Ed25519 key pair.
        
        Returns:
            tuple: (private_key_pem_bytes, public_key_pem_bytes)
        """
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
        """
        Generate an RSA-PSS key pair.
        
        Args:
            key_size: Size of the RSA key in bits (default: 2048)
            
        Returns:
            tuple: (private_key_pem_bytes, public_key_pem_bytes)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
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
    def save_key_to_file(key_pem: bytes, filepath: str) -> None:
        """
        Save a PEM-encoded key to a file.
        
        Args:
            key_pem: PEM-encoded key bytes
            filepath: Path to save the key file
        """
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_bytes(key_pem)

    @staticmethod
    def load_private_key(filepath: str):
        """
        Load a private key from a PEM file.
        
        Args:
            filepath: Path to the PEM file
            
        Returns:
            Private key object (Ed25519 or RSA)
        """
        key_data = Path(filepath).read_bytes()
        
        try:
            return serialization.load_pem_private_key(
                key_data, password=None, backend=default_backend()
            )
        except ValueError:
            raise ValueError(f"Invalid private key file: {filepath}")

    @staticmethod
    def load_public_key(filepath: str):
        """
        Load a public key from a PEM file.
        
        Args:
            filepath: Path to the PEM file
            
        Returns:
            Public key object (Ed25519 or RSA)
        """
        key_data = Path(filepath).read_bytes()
        
        try:
            return serialization.load_pem_public_key(
                key_data, backend=default_backend()
            )
        except ValueError:
            raise ValueError(f"Invalid public key file: {filepath}")

    @staticmethod
    def load_key_from_bytes(key_pem: bytes):
        """
        Load a key from PEM bytes.
        
        Args:
            key_pem: PEM-encoded key bytes
            
        Returns:
            Key object (private or public)
        """
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
            raise ValueError("Invalid key data: could not parse as private or public key")


class CryptoManager:
    """Handles digital signing and verification on contract parts."""

    def __init__(self, algorithm: str = "ed25519"):
        """
        Initialize the CryptoManager.
        
        Args:
            algorithm: Signing algorithm - "ed25519" (default) or "rsa-pss"
        """
        self.algorithm = algorithm.lower()
        if self.algorithm not in ("ed25519", "rsa-pss"):
            raise ValueError(f"Unsupported algorithm: {algorithm}. Use 'ed25519' or 'rsa-pss'.")

    def sign_part(self, part_id: str, contract_id: str, sequence_number: int,
                  content: str, private_key) -> dict:
        """
        Sign a single contract part and produce a signature structure.
        
        Args:
            part_id: Unique identifier for this part
            contract_id: Identifier of the parent contract
            sequence_number: Order number of this part
            content: The text content of this part
            private_key: Private key object for signing
            
        Returns:
            dict: Signed part with metadata, hash, and signature
        """
        # Compute content hash
        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()

        # Create the data to sign (canonical representation)
        data_to_sign = f"{contract_id}|{part_id}|{sequence_number}|{content_hash}".encode('utf-8')

        # Sign based on algorithm
        if self.algorithm == "ed25519":
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise TypeError("Expected Ed25519 private key")
            signature = private_key.sign(data_to_sign)
        else:  # rsa-pss
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise TypeError("Expected RSA private key")
            signature = private_key.sign(
                data_to_sign,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

        part_data = {
            "part_id": part_id,
            "contract_id": contract_id,
            "sequence_number": sequence_number,
            "content": content,
            "hash": content_hash,
            "signature": signature.hex(),
            "algorithm": self.algorithm
        }

        return part_data

    def verify_part(self, part_data: dict, public_key) -> bool:
        """
        Verify the signature of a single contract part.
        
        Args:
            part_data: dict containing part_id, contract_id, sequence_number,
                       hash, content, signature
            public_key: Public key object for verification
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        content_hash = hashlib.sha256(
            part_data["content"].encode('utf-8')
        ).hexdigest()

        # Check content integrity
        if content_hash != part_data["hash"]:
            return False

        data_to_verify = (
            f"{part_data['contract_id']}"
            f"|{part_data['part_id']}"
            f"|{part_data['sequence_number']}"
            f"|{content_hash}"
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
            else:  # rsa-pss
                if not isinstance(public_key, rsa.RSAPublicKey):
                    raise TypeError("Expected RSA public key")
                public_key.verify(
                    signature,
                    data_to_verify,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            return True
        except (InvalidSignature, TypeError, ValueError):
            return False

    def sign_manifest(self, manifest_data: str, private_key) -> bytes:
        """
        Sign the entire contract manifest.
        
        Args:
            manifest_data: JSON string of the manifest
            private_key: Private key object for signing
            
        Returns:
            bytes: Signature bytes
        """
        data = manifest_data.encode('utf-8')

        if self.algorithm == "ed25519":
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise TypeError("Expected Ed25519 private key")
            return private_key.sign(data)
        else:  # rsa-pss
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise TypeError("Expected RSA private key")
            return private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

    def verify_manifest(self, manifest_data: str, signature: bytes,
                        public_key) -> bool:
        """
        Verify the signature of a contract manifest.
        
        Args:
            manifest_data: JSON string of the manifest
            signature: Signature bytes
            public_key: Public key object for verification
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        data = manifest_data.encode('utf-8')

        try:
            if self.algorithm == "ed25519":
                if not isinstance(public_key, ed25519.Ed25519PublicKey):
                    raise TypeError("Expected Ed25519 public key")
                public_key.verify(signature, data)
            else:  # rsa-pss
                if not isinstance(public_key, rsa.RSAPublicKey):
                    raise TypeError("Expected RSA public key")
                public_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            return True
        except (InvalidSignature, TypeError, ValueError):
            return False