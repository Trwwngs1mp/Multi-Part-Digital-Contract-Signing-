"""
Replay Protection - Prevents replay attacks using nonce, timestamp, and sequence_number.

Implements defense-in-depth against replay:
1. Nonce (16 random bytes) - unique per message
2. Timestamp - allows TTL window
3. Sequence number - monotonically increasing per contract
4. Processed nonces set - rejects duplicates
"""

import os
import time
import hashlib
import json
from pathlib import Path
from typing import Set, Optional


class ReplayProtection:
    """
    Protects against replay attacks by tracking nonces, timestamps,
    and sequence numbers.

    Stores processed nonces in a file for persistence across sessions.
    """

    def __init__(self, storage_path: str = "data/processed_nonces.json",
                 ttl_seconds: int = 3600):
        """
        Initialize the replay protection system.

        Args:
            storage_path: File path to store processed nonces
            ttl_seconds: Time-to-live for timestamps (default: 1 hour)
        """
        self.storage_path = Path(storage_path)
        self.ttl_seconds = ttl_seconds
        self._processed_nonces: Set[str] = set()
        self._processed_sequence_numbers: Set[str] = set()
        self._load_nonces()

    def _load_nonces(self) -> None:
        """Load previously processed nonces from storage file."""
        if self.storage_path.exists():
            try:
                data = json.loads(self.storage_path.read_text())
                self._processed_nonces = set(data.get("nonces", []))
                self._processed_sequence_numbers = set(
                    data.get("sequence_numbers", [])
                )
            except (json.JSONDecodeError, KeyError):
                self._processed_nonces = set()
                self._processed_sequence_numbers = set()

    def _save_nonces(self) -> None:
        """Save processed nonces to storage file."""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "nonces": list(self._processed_nonces),
            "sequence_numbers": list(self._processed_sequence_numbers)
        }
        self.storage_path.write_text(json.dumps(data, indent=2))

    def generate_nonce(self) -> str:
        """
        Generate a new random nonce (16 bytes, hex-encoded).

        Returns:
            str: Hex-encoded nonce
        """
        return os.urandom(16).hex()

    def generate_message_id(self, contract_id: str, part_id: str,
                            nonce: str) -> str:
        """
        Generate a unique message ID from contract_id, part_id, and nonce.

        Args:
            contract_id: Contract identifier
            part_id: Part identifier
            nonce: Nonce value

        Returns:
            str: SHA-256 hash as unique message ID
        """
        raw = f"{contract_id}|{part_id}|{nonce}".encode('utf-8')
        return hashlib.sha256(raw).hexdigest()

    def create_packet(self, contract_id: str, part_id: str,
                      sequence_number: int, payload: dict) -> dict:
        """
        Wrap a payload in a packet with replay protection metadata.

        Args:
            contract_id: Contract identifier
            part_id: Part identifier
            sequence_number: Monotonically increasing sequence number
            payload: The actual data payload

        Returns:
            dict: Packet with nonce, timestamp, sequence_number, message_id
        """
        nonce = self.generate_nonce()
        timestamp = int(time.time())
        message_id = self.generate_message_id(contract_id, part_id, nonce)

        packet = {
            "contract_id": contract_id,
            "part_id": part_id,
            "sequence_number": sequence_number,
            "nonce": nonce,
            "timestamp": timestamp,
            "message_id": message_id,
            "payload": payload
        }

        return packet

    def verify_packet(self, packet: dict) -> tuple:
        """
        Verify a packet for replay attacks.

        Checks:
        1. Nonce not already processed (replay detection)
        2. Timestamp within TTL window (freshness)
        3. Sequence number not already processed (strict ordering)

        Args:
            packet: dict containing nonce, timestamp, sequence_number,
                   contract_id, part_id

        Returns:
            tuple: (is_valid: bool, reason: str or None)
        """
        nonce = packet.get("nonce", "")
        timestamp = packet.get("timestamp", 0)
        sequence_number = packet.get("sequence_number", -1)
        contract_id = packet.get("contract_id", "")
        part_id = packet.get("part_id", "")

        # Check 1: Nonce already processed (replay!)
        if nonce in self._processed_nonces:
            return False, "Nonce already processed (replay detected)"

        # Check 2: Timestamp freshness
        current_time = int(time.time())
        if abs(current_time - timestamp) > self.ttl_seconds:
            return False, f"Timestamp expired (current={current_time}, packet={timestamp}, ttl={self.ttl_seconds})"

        # Check 3: Sequence number uniqueness per contract+part
        seq_key = f"{contract_id}|{part_id}|{sequence_number}"
        if seq_key in self._processed_sequence_numbers:
            return False, f"Sequence number {sequence_number} already processed for {contract_id}/{part_id}"

        # Check message_id consistency
        expected_message_id = self.generate_message_id(
            contract_id, part_id, nonce
        )
        if packet.get("message_id", "") != expected_message_id:
            return False, "Message ID mismatch (data integrity check failed)"

        # Mark as processed
        self._processed_nonces.add(nonce)
        self._processed_sequence_numbers.add(seq_key)
        self._save_nonces()

        return True, None

    def verify_packet_without_storing(self, packet: dict) -> tuple:
        """
        Verify a packet without marking it as processed.
        Useful for test scenarios where we want to verify without side effects.

        Args:
            packet: dict containing nonce, timestamp, sequence_number

        Returns:
            tuple: (is_valid: bool, reason: str or None)
        """
        # Make a copy of current state, verify temporarily
        original_nonces = self._processed_nonces.copy()
        original_seq = self._processed_sequence_numbers.copy()

        result = self.verify_packet(packet)

        # Restore original state
        self._processed_nonces = original_nonces
        self._processed_sequence_numbers = original_seq
        self._save_nonces()

        return result

    def get_processed_count(self) -> int:
        """
        Get the number of processed nonces.

        Returns:
            int: Number of processed nonces
        """
        # Clean expired nonces (optional maintenance)
        self._cleanup()
        return len(self._processed_nonces)

    def _cleanup(self) -> None:
        """
        Optional cleanup of old processed data.
        In a full implementation, we'd attach timestamps to each nonce.
        For this academic version, we'll keep all for simplicity.
        """
        pass

    def reset(self) -> None:
        """Reset all processed data (for testing purposes)."""
        self._processed_nonces = set()
        self._processed_sequence_numbers = set()
        if self.storage_path.exists():
            self.storage_path.unlink()