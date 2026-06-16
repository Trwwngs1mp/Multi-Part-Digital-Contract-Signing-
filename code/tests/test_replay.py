"""
Test: Replay - Tests detection of replayed packets and protection mechanisms.

Verifies:
- Nonce uniqueness (same nonce used twice is rejected)
- Timestamp expiration (old packets rejected)
- Sequence number tracking (duplicate sequence rejected)
- Message ID consistency check
"""

import pytest
import time
import json
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.utils.replay_protection import ReplayProtection


@pytest.fixture
def replay_protection(tmp_path):
    """Create a ReplayProtection instance with temp storage."""
    storage_path = tmp_path / "nonces.json"
    rp = ReplayProtection(storage_path=str(storage_path), ttl_seconds=3600)
    rp.reset()
    return rp


def test_nonce_generation(replay_protection):
    """Test that nonce generation produces unique values."""
    nonce1 = replay_protection.generate_nonce()
    nonce2 = replay_protection.generate_nonce()

    assert len(nonce1) == 32  # 16 bytes = 32 hex chars
    assert nonce1 != nonce2


def test_create_packet(replay_protection):
    """Test that packet creation includes all required fields."""
    payload = {"part_id": "PART-001", "content": "Test content"}
    packet = replay_protection.create_packet(
        contract_id="CONTRACT-001",
        part_id="PART-001",
        sequence_number=1,
        payload=payload
    )

    assert packet["contract_id"] == "CONTRACT-001"
    assert packet["part_id"] == "PART-001"
    assert packet["sequence_number"] == 1
    assert packet["nonce"] is not None
    assert packet["timestamp"] is not None
    assert packet["message_id"] is not None
    assert packet["payload"] == payload

    # Verify message_id is a SHA-256 hash (64 hex chars)
    assert len(packet["message_id"]) == 64


def test_valid_packet_accepted(replay_protection):
    """Test that a valid packet is accepted."""
    packet = replay_protection.create_packet(
        contract_id="CONTRACT-001",
        part_id="PART-001",
        sequence_number=1,
        payload={"data": "test"}
    )

    is_valid, reason = replay_protection.verify_packet(packet)
    assert is_valid is True, f"Valid packet should be accepted: {reason}"
    assert reason is None


def test_replay_detected(replay_protection):
    """Test that replaying the same packet is detected."""
    packet = replay_protection.create_packet(
        contract_id="CONTRACT-001",
        part_id="PART-001",
        sequence_number=1,
        payload={"data": "test"}
    )

    # First use - should be valid
    is_valid, reason = replay_protection.verify_packet(packet)
    assert is_valid is True

    # Second use with same nonce - should be rejected
    is_valid, reason = replay_protection.verify_packet(packet)
    assert is_valid is False, "Replay should be detected"
    assert "replay" in reason.lower()


def test_replay_across_packets(replay_protection):
    """Test that different packets are all accepted."""
    for i in range(10):
        packet = replay_protection.create_packet(
            contract_id="CONTRACT-001",
            part_id=f"PART-{i+1:03d}",
            sequence_number=i + 1,
            payload={"seq": i + 1}
        )

        is_valid, reason = replay_protection.verify_packet(packet)
        assert is_valid is True, f"Packet {i+1} should be valid: {reason}"

    assert replay_protection.get_processed_count() == 10


def test_duplicate_sequence_rejected(replay_protection):
    """Test that same sequence number for same contract+part is rejected."""
    packet1 = replay_protection.create_packet(
        contract_id="CONTRACT-001",
        part_id="PART-001",
        sequence_number=1,
        payload={"data": "first"}
    )

    is_valid, reason = replay_protection.verify_packet(packet1)
    assert is_valid is True

    # Create new packet with same sequence number
    packet2 = replay_protection.create_packet(
        contract_id="CONTRACT-001",
        part_id="PART-001",
        sequence_number=1,
        payload={"data": "second"}
    )

    is_valid, reason = replay_protection.verify_packet(packet2)
    assert is_valid is False, "Duplicate sequence should be rejected"
    assert "sequence" in reason.lower()


def test_different_contracts_independent(replay_protection):
    """Test that sequence numbers are independent across contracts."""
    for i in range(3):
        packet = replay_protection.create_packet(
            contract_id="CONTRACT-A",
            part_id="PART-001",
            sequence_number=i + 1,
            payload={"seq": i + 1}
        )
        is_valid, reason = replay_protection.verify_packet(packet)
        assert is_valid is True

    # Same sequence number for different contract should work
    packet = replay_protection.create_packet(
        contract_id="CONTRACT-B",
        part_id="PART-001",
        sequence_number=1,
        payload={"data": "different contract"}
    )
    is_valid, reason = replay_protection.verify_packet(packet)
    assert is_valid is True, "Different contracts should have independent sequences"


def test_timestamp_expiry():
    """Test that expired timestamps are rejected."""
    # Create a replay protection with very short TTL
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        storage_path = f.name

    try:
        rp = ReplayProtection(storage_path=storage_path, ttl_seconds=1)

        packet = rp.create_packet(
            contract_id="TEST",
            part_id="PART-001",
            sequence_number=1,
            payload={"data": "test"}
        )

        # Manually set old timestamp
        packet["timestamp"] = int(time.time()) - 10  # 10 seconds ago

        # Verify - should fail due to expired TTL (1 second)
        is_valid, reason = rp.verify_packet_without_storing(packet)
        assert is_valid is False, "Expired timestamp should be rejected"
        assert "expired" in reason.lower()

    finally:
        Path(storage_path).unlink(missing_ok=True)


def test_message_id_consistency(replay_protection):
    """Test that message_id mismatch is detected."""
    packet = replay_protection.create_packet(
        contract_id="CONTRACT-001",
        part_id="PART-001",
        sequence_number=1,
        payload={"data": "test"}
    )

    # Corrupt the message_id
    original_message_id = packet["message_id"]
    packet["message_id"] = "0" * 64

    is_valid, reason = replay_protection.verify_packet(packet)
    assert is_valid is False, "Message ID mismatch should be detected"
    assert "Message ID" in reason


def test_verify_without_storing(replay_protection):
    """Test that verify_packet_without_storing doesn't mark as processed."""
    packet = replay_protection.create_packet(
        contract_id="CONTRACT-001",
        part_id="PART-001",
        sequence_number=1,
        payload={"data": "test"}
    )

    # Verify without storing - should pass
    is_valid, reason = replay_protection.verify_packet_without_storing(packet)
    assert is_valid is True

    # After verify_without_storing, the nonce should NOT be marked as processed
    # So a subsequent normal verify should work
    is_valid, reason = replay_protection.verify_packet(packet)
    assert is_valid is True


def test_persistence(tmp_path):
    """Test that processed nonces persist across instances."""
    storage_path = tmp_path / "nonces.json"

    # First instance
    rp1 = ReplayProtection(storage_path=str(storage_path), ttl_seconds=3600)
    rp1.reset()

    packet1 = rp1.create_packet(
        contract_id="PERSISTENCE-TEST",
        part_id="PART-001",
        sequence_number=1,
        payload={"data": "test"}
    )
    is_valid, _ = rp1.verify_packet(packet1)
    assert is_valid is True

    # Second instance with same storage file
    rp2 = ReplayProtection(storage_path=str(storage_path), ttl_seconds=3600)

    # Try to replay the same packet - should be rejected
    is_valid, reason = rp2.verify_packet(packet1)
    assert is_valid is False, "Replay across instances should be detected"
    assert "replay" in reason.lower()


def test_reset_functionality(replay_protection):
    """Test that reset clears all processed data."""
    packet = replay_protection.create_packet(
        contract_id="RESET-TEST",
        part_id="PART-001",
        sequence_number=1,
        payload={"data": "test"}
    )

    is_valid, _ = replay_protection.verify_packet(packet)
    assert is_valid is True
    assert replay_protection.get_processed_count() == 1

    # Reset
    replay_protection.reset()
    assert replay_protection.get_processed_count() == 0

    # Same packet should now be accepted again (since we reset)
    # Note: This is for testing; in production we'd never want this
    is_valid, reason = replay_protection.verify_packet(packet)
    assert is_valid is True