"""
Contract Handler - Manages splitting, verification, and reassembly of multi-part contracts.

Detects: missing parts, extra parts, reordered parts, modified content.
"""

import json
import hashlib
import uuid
from typing import List, Dict, Optional, Tuple
from pathlib import Path

from ..crypto.crypto_manager import CryptoManager, KeyManager
from ..utils.logger import SecurityLogger
from ..utils.replay_protection import ReplayProtection


class ContractHandler:
    """
    Handles multi-part digital contract operations:
    - Splitting contracts into parts
    - Verifying each part's signature
    - Detecting anomalies (missing, extra, reordered, modified)
    - Reassembling contracts after verification
    """

    def __init__(self, crypto_manager: CryptoManager,
                 logger: SecurityLogger,
                 replay_protection: ReplayProtection = None):
        """
        Initialize the ContractHandler.

        Args:
            crypto_manager: CryptoManager instance for signing/verification
            logger: SecurityLogger instance for logging
            replay_protection: Optional ReplayProtection instance
        """
        self.crypto = crypto_manager
        self.logger = logger
        self.replay = replay_protection or ReplayProtection(
            storage_path="data/processed_nonces.json"
        )

    def split_contract(self, contract_text: str, contract_id: str = None,
                       num_parts: int = 3) -> Tuple[str, List[dict]]:
        """
        Split a contract text into multiple parts and sign each part.

        Args:
            contract_text: Full contract text content
            contract_id: Optional contract identifier (auto-generated if None)
            num_parts: Number of parts to split into (default: 3)

        Returns:
            tuple: (manifest_json_string, list_of_part_dicts)
        """
        if contract_id is None:
            contract_id = f"CONTRACT-{uuid.uuid4().hex[:8].upper()}"

        # Load the sender's private key
        key_filename = f"{self.crypto.algorithm}_private.pem"
        key_path = KeyManager.DEFAULT_KEY_DIR / key_filename
        if not key_path.exists():
            raise FileNotFoundError(
                f"No private key found at {key_path}. "
                f"Generate keys first using: python cli.py generate-keys"
            )
        private_key = KeyManager.load_private_key(str(key_path))

        # Split text into roughly equal parts
        lines = contract_text.split('\n')
        total_lines = len(lines)
        part_size = max(1, total_lines // num_parts)

        parts = []
        for i in range(num_parts):
            start = i * part_size
            end = (i + 1) * part_size if i < num_parts - 1 else total_lines
            part_content = '\n'.join(lines[start:end])

            part_id = f"PART-{i+1:03d}"
            sequence_number = i + 1

            # Sign the part
            part_data = self.crypto.sign_part(
                part_id=part_id,
                contract_id=contract_id,
                sequence_number=sequence_number,
                content=part_content,
                private_key=private_key
            )

            parts.append(part_data)
            self.logger.log_signing(part_id, contract_id)

        # Build and sign manifest
        manifest_data = self._build_manifest(contract_id, parts)
        manifest_json = json.dumps(manifest_data, indent=2)

        # Sign the manifest
        manifest_signature = self.crypto.sign_manifest(manifest_json, private_key)
        manifest_data["manifest_signature"] = manifest_signature.hex()
        manifest_data["signature_algorithm"] = self.crypto.algorithm

        manifest_json = json.dumps(manifest_data, indent=2)
        self.logger.log_manifest_signed(contract_id, len(parts))

        return manifest_json, parts

    def verify_contract(self, manifest_json: str, parts: List[dict],
                        public_key_path: str = None) -> Tuple[bool, str, Optional[str]]:
        """
        Verify the integrity and authenticity of a multi-part contract.

        Checks:
        1. Manifest signature validity
        2. Each part's signature validity
        3. No missing parts (based on manifest)
        4. No extra parts (beyond manifest)
        5. Correct sequence order
        6. Content integrity (hash match)

        Args:
            manifest_json: JSON string of the contract manifest
            parts: List of signed part dictionaries
            public_key_path: Path to public key PEM file (uses default if None)

        Returns:
            tuple: (is_valid: bool, message: str, reassembled_contract: str or None)
        """
        # Load public key
        if public_key_path is None:
            key_path = KeyManager.DEFAULT_KEY_DIR / "ed25519_public.pem"
            if not key_path.exists():
                return False, f"No public key found at {key_path}. Generate keys first.", None
            public_key_path = str(key_path)

        try:
            public_key = KeyManager.load_public_key(public_key_path)
        except ValueError as e:
            return False, f"Failed to load public key: {str(e)}", None

        # Parse manifest
        try:
            manifest = json.loads(manifest_json)
        except json.JSONDecodeError as e:
            return False, f"Invalid manifest JSON: {str(e)}", None

        # Verify manifest signature
        expected_parts_info = manifest.get("parts", [])
        expected_count = len(expected_parts_info)
        contract_id = manifest.get("contract_id", "UNKNOWN")

        # Remove signature from manifest before verification
        manifest_signature_hex = manifest.get("manifest_signature", "")
        if not manifest_signature_hex:
            return False, "Manifest has no signature", None

        # Recreate manifest JSON without the signature for verification
        manifest_for_verify = {
            "contract_id": manifest["contract_id"],
            "total_parts": manifest["total_parts"],
            "parts": expected_parts_info
        }
        manifest_for_verify_json = json.dumps(manifest_for_verify, indent=2)

        manifest_signature = bytes.fromhex(manifest_signature_hex)

        manifest_valid = self.crypto.verify_manifest(
            manifest_for_verify_json, manifest_signature, public_key
        )

        if not manifest_valid:
            self.logger.log_manifest_verified(contract_id, False)
            return False, "Manifest signature verification FAILED", None

        self.logger.log_manifest_verified(contract_id, True)

        # --- Check 1: Detect missing parts ---
        part_map = {}
        for part in parts:
            part_id = part.get("part_id", "")
            part_map[part_id] = part

        expected_ids = [p["part_id"] for p in expected_parts_info]
        actual_ids = list(part_map.keys())

        missing_ids = set(expected_ids) - set(actual_ids)
        if missing_ids:
            self.logger.log_integrity_error(
                str(missing_ids), contract_id,
                f"Missing parts: {missing_ids}"
            )
            return False, f"Missing parts detected: {missing_ids}", None

        # --- Check 2: Detect extra parts ---
        extra_ids = set(actual_ids) - set(expected_ids)
        if extra_ids:
            self.logger.log_integrity_error(
                str(extra_ids), contract_id,
                f"Extra parts detected: {extra_ids}"
            )
            return False, f"Extra parts detected: {extra_ids}", None

        # --- Check 3: Verify sequence order ---
        # Sort by sequence_number from manifest
        sorted_expected = sorted(expected_parts_info, key=lambda p: p["sequence_number"])
        sorted_actual = sorted(parts, key=lambda p: p["sequence_number"])

        for i, (exp, act) in enumerate(zip(sorted_expected, sorted_actual)):
            if exp["part_id"] != act["part_id"]:
                self.logger.log_tampering_detected(
                    contract_id, f"pos={i+1}",
                    f"Sequence order mismatch: expected {exp['part_id']} but got {act['part_id']}"
                )
                return False, (
                    f"Sequence order violation at position {i+1}: "
                    f"expected {exp['part_id']} but found {act['part_id']}"
                ), None

        # --- Check 4: Verify each part's signature and integrity ---
        for part in parts:
            part_id = part.get("part_id", "")
            seq_num = part.get("sequence_number", 0)

            is_valid = self.crypto.verify_part(part, public_key)
            self.logger.log_verification(part_id, contract_id, is_valid)

            if not is_valid:
                self.logger.log_integrity_error(
                    part_id, contract_id,
                    "Part signature or hash verification FAILED"
                )
                return False, (
                    f"Part {part_id} (seq={seq_num}) "
                    f"signature or content integrity verification FAILED"
                ), None

        # --- All checks passed: Reassemble contract ---
        reassembled = '\n'.join(
            part["content"] for part in sorted_actual
        )

        return True, (
            f"Contract '{contract_id}' verification PASSED: "
            f"all {len(parts)} parts valid, "
            f"no missing/extra/reordered parts, "
            f"manifest signature confirmed"
        ), reassembled

    def _build_manifest(self, contract_id: str, parts: List[dict]) -> dict:
        """
        Build a manifest for the contract.

        Args:
            contract_id: Contract identifier
            parts: List of signed part dictionaries

        Returns:
            dict: Manifest data
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

        return manifest

    def save_contract_parts(self, parts: List[dict],
                            output_dir: str = "output") -> str:
        """
        Save contract parts to individual files.

        Args:
            parts: List of signed part dictionaries
            output_dir: Output directory path

        Returns:
            str: Path to output directory
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        for part in parts:
            part_file = output_path / f"{part['part_id']}.json"
            part_file.write_text(json.dumps(part, indent=2))

        return str(output_path)

    def load_contract_parts(self, input_dir: str) -> List[dict]:
        """
        Load contract parts from individual JSON files.

        Args:
            input_dir: Directory containing part JSON files

        Returns:
            List of part dictionaries
        """
        parts = []
        input_path = Path(input_dir)

        for json_file in sorted(input_path.glob("PART-*.json")):
            part = json.loads(json_file.read_text())
            parts.append(part)

        return parts

    def modify_part_content(self, part: dict, new_content: str) -> dict:
        """
        Modify the content of a part (for testing tampering scenarios).

        WARNING: This intentionally corrupts the part for testing purposes.

        Args:
            part: Original part dictionary
            new_content: New content to replace

        Returns:
            dict: Modified part (signature now invalid)
        """
        modified = dict(part)
        modified["content"] = new_content
        # Hash is now stale, signature won't match
        return modified

    def remove_part(self, parts: List[dict], part_id: str) -> List[dict]:
        """
        Remove a part from the list (for testing scenarios).

        Args:
            parts: List of part dictionaries
            part_id: ID of part to remove

        Returns:
            List: Modified part list with part removed
        """
        return [p for p in parts if p["part_id"] != part_id]

    def reorder_parts(self, parts: List[dict], new_order: List[str]) -> List[dict]:
        """
        Reorder parts (for testing scenarios).

        Args:
            parts: List of part dictionaries
            new_order: List of part_ids in the desired order

        Returns:
            List: Reordered part list
        """
        part_map = {p["part_id"]: p for p in parts}
        return [part_map[pid] for pid in new_order if pid in part_map]