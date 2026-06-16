"""
Contract Signer - Client-side module for signing contracts and managing keys.
"""

import json
import os
from pathlib import Path
from typing import Optional

from ..crypto.crypto_manager import CryptoManager, KeyManager
from ..server.contract_handler import ContractHandler
from ..server.manifest import ManifestManager
from ..utils.logger import SecurityLogger


class ContractSigner:
    """
    Client-side interface for contract signing operations.

    Provides high-level methods for:
    - Key generation
    - Contract signing (split into parts + sign each part + sign manifest)
    - Contract verification
    """

    def __init__(self, algorithm: str = "ed25519", log_dir: str = "logs"):
        """
        Initialize the ContractSigner.

        Args:
            algorithm: Signing algorithm ("ed25519" or "rsa-pss")
            log_dir: Directory for log files
        """
        self.algorithm = algorithm
        self.logger = SecurityLogger(log_dir=log_dir)
        self.crypto = CryptoManager(algorithm=algorithm)
        self.contract_handler = ContractHandler(
            crypto_manager=self.crypto,
            logger=self.logger
        )
        self.manifest_manager = ManifestManager(
            crypto_manager=self.crypto,
            logger=self.logger
        )

    def generate_keys(self, key_dir: Optional[str] = None) -> tuple:
        """
        Generate a new key pair for contract signing.

        Args:
            key_dir: Directory to store keys (uses default ~/.contract_signing_keys if None)

        Returns:
            tuple: (private_key_path, public_key_path)
        """
        if key_dir is None:
            key_dir = str(KeyManager.DEFAULT_KEY_DIR)

        key_dir_path = Path(key_dir)
        key_dir_path.mkdir(parents=True, exist_ok=True)

        if self.algorithm == "ed25519":
            priv_pem, pub_pem = KeyManager.generate_ed25519_key_pair()
        else:
            priv_pem, pub_pem = KeyManager.generate_rsa_pss_key_pair()

        priv_path = key_dir_path / f"{self.algorithm}_private.pem"
        pub_path = key_dir_path / f"{self.algorithm}_public.pem"

        KeyManager.save_key_to_file(priv_pem, str(priv_path))
        KeyManager.save_key_to_file(pub_pem, str(pub_path))

        key_size = None
        if self.algorithm == "rsa-pss":
            key_size = "2048"

        self.logger.log_key_generation(self.algorithm, key_size)
        print(f"[OK] Keys generated successfully.")
        print(f"      Private key: {priv_path}")
        print(f"      Public key : {pub_path}")
        print(f"      Algorithm  : {self.algorithm}")
        print("")
        print("IMPORTANT: Share your PUBLIC key with the recipient.")
        print("          Keep your PRIVATE key secret and secure.")

        return str(priv_path), str(pub_path)

    def sign_contract(self, contract_path: str, num_parts: int = 3,
                      output_dir: str = "output") -> tuple:
        """
        Sign a contract by splitting it into parts and creating a manifest.

        Args:
            contract_path: Path to the contract text file
            num_parts: Number of parts to split into
            output_dir: Directory for output files

        Returns:
            tuple: (manifest_path, parts_dir)
        """
        # Read contract
        contract_text = Path(contract_path).read_text(encoding='utf-8')
        contract_name = Path(contract_path).stem

        # Split and sign
        manifest_json, parts = self.contract_handler.split_contract(
            contract_text=contract_text,
            contract_id=contract_name,
            num_parts=num_parts
        )

        # Save parts
        parts_dir = Path(output_dir) / contract_name / "parts"
        parts_dir.mkdir(parents=True, exist_ok=True)

        for part in parts:
            part_file = parts_dir / f"{part['part_id']}.json"
            part_file.write_text(json.dumps(part, indent=2))

        # Save manifest
        manifest_dir = Path(output_dir) / contract_name
        manifest_path = manifest_dir / "manifest.json"
        manifest_path.write_text(manifest_json)

        print(f"[OK] Contract signed successfully.")
        print(f"      Contract ID: {contract_name}")
        print(f"      Parts      : {num_parts}")
        print(f"      Parts dir  : {parts_dir}")
        print(f"      Manifest   : {manifest_path}")

        return str(manifest_path), str(parts_dir)

    def verify_contract(self, manifest_path: str, parts_dir: str,
                        public_key_path: Optional[str] = None) -> bool:
        """
        Verify a signed contract.

        Args:
            manifest_path: Path to the manifest JSON file
            parts_dir: Directory containing the part JSON files
            public_key_path: Path to the public key PEM file

        Returns:
            bool: True if verification passed
        """
        # Load manifest
        manifest_json = Path(manifest_path).read_text()
        manifest = json.loads(manifest_json)

        # Load parts
        parts = []
        parts_dir_path = Path(parts_dir)
        for json_file in sorted(parts_dir_path.glob("PART-*.json")):
            parts.append(json.loads(json_file.read_text()))

        contract_id = manifest.get("contract_id", "UNKNOWN")
        print(f"\n--- Verifying Contract: {contract_id} ---")
        print(f"  Parts found: {len(parts)}")
        print(f"  Algorithm  : {manifest.get('signature_algorithm', 'unknown')}")
        print(f"  Verifying...")

        # Determine default public key path
        if public_key_path is None:
            algorithm = manifest.get("signature_algorithm", "ed25519")
            key_dir = KeyManager.DEFAULT_KEY_DIR
            public_key_path = str(key_dir / f"{algorithm}_public.pem")

        # Verify
        is_valid, message, reassembled = self.contract_handler.verify_contract(
            manifest_json=manifest_json,
            parts=parts,
            public_key_path=public_key_path
        )

        print(f"\nResult: {'✓ PASS' if is_valid else '✗ FAIL'}")
        print(f"  {message}")

        if is_valid and reassembled:
            # Optionally save reassembled contract
            reassembled_path = Path(parts_dir).parent / "reassembled_contract.txt"
            reassembled_path.write_text(reassembled)
            print(f"  Reassembled contract saved to: {reassembled_path}")

        return is_valid