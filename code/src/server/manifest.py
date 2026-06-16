"""
Manifest Manager - Handles creation, validation, and management of contract manifests.

The manifest is a digitally signed JSON document that lists all parts of a contract
with their IDs, sequence numbers, and hashes.
"""

import json
import uuid
from typing import List, Dict, Optional, Tuple
from pathlib import Path

from ..crypto.crypto_manager import CryptoManager, KeyManager
from ..utils.logger import SecurityLogger


class ManifestManager:
    """
    Manages contract manifest operations independent of the full contract flow.
    Useful for standalone manifest handling and testing.
    """

    def __init__(self, crypto_manager: CryptoManager, logger: SecurityLogger):
        """
        Initialize the ManifestManager.

        Args:
            crypto_manager: CryptoManager instance
            logger: SecurityLogger instance
        """
        self.crypto = crypto_manager
        self.logger = logger

    def create_manifest(self, contract_id: str, parts: List[dict]) -> dict:
        """
        Create a manifest from a list of contract parts.

        Args:
            contract_id: Contract identifier
            parts: List of signed part dictionaries

        Returns:
            dict: Complete manifest dictionary including signature
        """
        parts_info = []
        for part in parts:
            parts_info.append({
                "part_id": part["part_id"],
                "sequence_number": part["sequence_number"],
                "hash": part["hash"]
            })

        manifest = {
            "contract_id": contract_id,
            "total_parts": len(parts),
            "parts": parts_info
        }

        # Load sender's private key and sign
        key_dir = KeyManager.DEFAULT_KEY_DIR
        private_key_path = key_dir / f"{self.crypto.algorithm}_private.pem"
        if not private_key_path.exists():
            raise FileNotFoundError(
                f"No private key found at {private_key_path}. "
                f"Generate keys first."
            )

        private_key = KeyManager.load_private_key(str(private_key_path))
        manifest_json = json.dumps(manifest, indent=2)
        signature = self.crypto.sign_manifest(manifest_json, private_key)

        manifest["manifest_signature"] = signature.hex()
        manifest["signature_algorithm"] = self.crypto.algorithm

        self.logger.log_manifest_signed(contract_id, len(parts))
        return manifest

    def validate_manifest(self, manifest: dict,
                          public_key_path: str = None) -> Tuple[bool, str]:
        """
        Validate a manifest's signature and structure.

        Args:
            manifest: Manifest dictionary
            public_key_path: Path to public key PEM file

        Returns:
            tuple: (is_valid: bool, message: str)
        """
        if public_key_path is None:
            key_dir = KeyManager.DEFAULT_KEY_DIR
            public_key_path = str(key_dir / f"{self.crypto.algorithm}_public.pem")

        if not Path(public_key_path).exists():
            return False, f"Public key not found: {public_key_path}"

        public_key = KeyManager.load_public_key(public_key_path)

        # Check required fields
        required = ["contract_id", "total_parts", "parts", "manifest_signature"]
        for field in required:
            if field not in manifest:
                return False, f"Manifest missing required field: {field}"

        # Check parts structure
        for i, part in enumerate(manifest["parts"]):
            for field in ["part_id", "sequence_number", "hash"]:
                if field not in part:
                    return False, f"Part {i} missing required field: {field}"

        # Recreate manifest JSON without signature for verification
        manifest_for_verify = {
            "contract_id": manifest["contract_id"],
            "total_parts": manifest["total_parts"],
            "parts": manifest["parts"]
        }
        manifest_json = json.dumps(manifest_for_verify, indent=2)

        signature = bytes.fromhex(manifest["manifest_signature"])

        is_valid = self.crypto.verify_manifest(
            manifest_json, signature, public_key
        )

        self.logger.log_manifest_verified(
            manifest["contract_id"], is_valid
        )

        if is_valid:
            return True, "Manifest signature valid"
        else:
            return False, "Manifest signature INVALID"

    def get_part_sequence(self, manifest: dict) -> List[str]:
        """
        Get the expected part sequence from the manifest.

        Args:
            manifest: Manifest dictionary

        Returns:
            List of part_ids in the expected order
        """
        sorted_parts = sorted(
            manifest.get("parts", []),
            key=lambda p: p["sequence_number"]
        )
        return [p["part_id"] for p in sorted_parts]

    def verify_manifest_against_parts(self, manifest: dict,
                                      parts: List[dict]) -> Tuple[bool, str]:
        """
        Verify that the manifest matches the actual parts list.

        Args:
            manifest: Manifest dictionary
            parts: List of part dictionaries

        Returns:
            tuple: (is_valid: bool, message: str)
        """
        expected_count = manifest.get("total_parts", 0)
        actual_count = len(parts)

        if expected_count != actual_count:
            return False, (
                f"Part count mismatch: manifest says {expected_count}, "
                f"but got {actual_count}"
            )

        expected_parts = manifest.get("parts", [])
        for exp_part in expected_parts:
            # Find matching part
            matching = [p for p in parts if p["part_id"] == exp_part["part_id"]]
            if not matching:
                return False, (
                    f"Part {exp_part['part_id']} expected by manifest but not found"
                )

            actual_part = matching[0]

            # Check sequence number
            if actual_part["sequence_number"] != exp_part["sequence_number"]:
                return False, (
                    f"Sequence number mismatch for {exp_part['part_id']}: "
                    f"manifest says {exp_part['sequence_number']}, "
                    f"but got {actual_part['sequence_number']}"
                )

            # Check hash
            if actual_part["hash"] != exp_part["hash"]:
                return False, (
                    f"Hash mismatch for {exp_part['part_id']}: "
                    f"content modified"
                )

        return True, "All parts match manifest"

    def save_manifest(self, manifest: dict, filepath: str) -> None:
        """
        Save a manifest to a JSON file.

        Args:
            manifest: Manifest dictionary
            filepath: Path to save the manifest
        """
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        Path(filepath).write_text(json.dumps(manifest, indent=2))

    def load_manifest(self, filepath: str) -> dict:
        """
        Load a manifest from a JSON file.

        Args:
            filepath: Path to the manifest file

        Returns:
            dict: Manifest dictionary
        """
        return json.loads(Path(filepath).read_text())

    def generate_contract_id(self) -> str:
        """
        Generate a unique contract ID.

        Returns:
            str: Unique contract identifier
        """
        return f"CONTRACT-{uuid.uuid4().hex[:12].upper()}"