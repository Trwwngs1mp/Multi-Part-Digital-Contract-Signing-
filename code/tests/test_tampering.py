"""
Test: Tampering - Tests detection of modified, missing, reordered, and extra parts.

Verifies:
- Detection of modified content (hash mismatch)
- Detection of missing parts
- Detection of reordered parts
- Detection of extra parts
"""

import pytest
import json
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.crypto.crypto_manager import CryptoManager, KeyManager
from src.server.contract_handler import ContractHandler
from src.utils.logger import SecurityLogger


SAMPLE_CONTRACT = """HỢP ĐỒNG MẪU
Điều 1: Nội dung
Bên A đồng ý cung cấp dịch vụ cho Bên B.
Điều 2: Thanh toán
Giá trị hợp đồng: 100.000.000 VNĐ.
Điều 3: Hiệu lực
Hợp đồng có hiệu lực từ ngày ký.
"""


@pytest.fixture
def setup_handler(tmp_path):
    """Set up a ContractHandler with fresh keys for testing."""
    # Generate keys
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    priv_pem, pub_pem = KeyManager.generate_ed25519_key_pair()
    KeyManager.save_key_to_file(priv_pem, str(key_dir / "ed25519_private.pem"))
    KeyManager.save_key_to_file(pub_pem, str(key_dir / "ed25519_public.pem"))

    # Point default key dir to temp
    import src.crypto.crypto_manager as cm
    original = cm.KeyManager.DEFAULT_KEY_DIR
    cm.KeyManager.DEFAULT_KEY_DIR = key_dir

    crypto = CryptoManager(algorithm="ed25519")
    logger = SecurityLogger(log_dir=str(tmp_path / "logs"))
    handler = ContractHandler(crypto_manager=crypto, logger=logger)

    # Split a contract for testing
    manifest_json, parts = handler.split_contract(
        contract_text=SAMPLE_CONTRACT,
        contract_id="TAMPER-TEST",
        num_parts=3
    )

    manifest = json.loads(manifest_json)

    yield {
        "handler": handler,
        "manifest": manifest,
        "manifest_json": manifest_json,
        "parts": parts,
        "key_dir": key_dir,
        "original_default_key_dir": original
    }

    # Restore
    import src.crypto.crypto_manager as cm
    cm.KeyManager.DEFAULT_KEY_DIR = original


def test_detect_modified_content(setup_handler):
    """Test that modifying a part's content is detected."""
    handler = setup_handler["handler"]
    manifest_json = setup_handler["manifest_json"]
    parts = setup_handler["parts"]
    key_dir = setup_handler["key_dir"]

    # Modify the content of part 2
    modified_parts = list(parts)
    original_content = modified_parts[1]["content"]
    modified_parts[1] = handler.modify_part_content(
        modified_parts[1],
        "THIS CONTENT HAS BEEN TAMPERED WITH!"
    )

    is_valid, message, reassembled = handler.verify_contract(
        manifest_json=manifest_json,
        parts=modified_parts,
        public_key_path=str(key_dir / "ed25519_public.pem")
    )

    assert is_valid is False, "Verification should fail when content is modified"
    assert "FAILED" in message or "Integrity" in message or "invalid" in message.lower()


def test_detect_missing_part(setup_handler):
    """Test that removing a part is detected."""
    handler = setup_handler["handler"]
    manifest_json = setup_handler["manifest_json"]
    parts = setup_handler["parts"]
    key_dir = setup_handler["key_dir"]

    # Remove part 2
    modified_parts = handler.remove_part(parts, "PART-002")

    assert len(modified_parts) == 2

    is_valid, message, reassembled = handler.verify_contract(
        manifest_json=manifest_json,
        parts=modified_parts,
        public_key_path=str(key_dir / "ed25519_public.pem")
    )

    assert is_valid is False, "Verification should fail when a part is missing"
    assert "Missing" in message


def test_detect_reordered_parts(setup_handler):
    """Test that reordering parts is detected."""
    handler = setup_handler["handler"]
    manifest_json = setup_handler["manifest_json"]
    parts = setup_handler["parts"]
    key_dir = setup_handler["key_dir"]

    # Swap sequence numbers to create actual reordering
    # The verify_contract sorts by sequence_number, so we need to actually
    # modify sequence_numbers to simulate reordering
    swapped_parts = []
    for part in parts:
        p = dict(part)
        if p["part_id"] == "PART-001":
            p["sequence_number"] = 3
        elif p["part_id"] == "PART-003":
            p["sequence_number"] = 1
        swapped_parts.append(p)

    is_valid, message, reassembled = handler.verify_contract(
        manifest_json=manifest_json,
        parts=swapped_parts,
        public_key_path=str(key_dir / "ed25519_public.pem")
    )

    assert is_valid is False, "Verification should fail when parts are reordered"
    assert "order" in message.lower() or "sequence" in message.lower()


def test_detect_extra_part(setup_handler):
    """Test that adding an extra part is detected."""
    handler = setup_handler["handler"]
    manifest_json = setup_handler["manifest_json"]
    parts = setup_handler["parts"]
    key_dir = setup_handler["key_dir"]

    # Create a fake extra part by duplicating and modifying one
    extra_part = dict(parts[0])
    extra_part["part_id"] = "PART-099"
    extra_part["sequence_number"] = 99
    extra_part["content"] = "This is an extra fake part."
    # This will fail signature check, but first the extra part check triggers

    modified_parts = list(parts) + [extra_part]

    is_valid, message, reassembled = handler.verify_contract(
        manifest_json=manifest_json,
        parts=modified_parts,
        public_key_path=str(key_dir / "ed25519_public.pem")
    )

    assert is_valid is False, "Verification should fail with an extra part"
    assert "Extra" in message or "extra" in message


def test_detect_hash_tampering(setup_handler):
    """Test that tampering with the hash field is detected."""
    handler = setup_handler["handler"]
    manifest_json = setup_handler["manifest_json"]
    parts = setup_handler["parts"]
    key_dir = setup_handler["key_dir"]

    # Corrupt the hash of part 1
    modified_parts = []
    for i, part in enumerate(parts):
        p = dict(part)
        if i == 0:
            p["hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
        modified_parts.append(p)

    is_valid, message, reassembled = handler.verify_contract(
        manifest_json=manifest_json,
        parts=modified_parts,
        public_key_path=str(key_dir / "ed25519_public.pem")
    )

    assert is_valid is False, "Verification should fail when hash is tampered"
    assert "FAILED" in message or "Integrity" in message


def test_verify_valid_flow_still_works(setup_handler):
    """Test that the valid flow still works with these keys."""
    handler = setup_handler["handler"]
    manifest_json = setup_handler["manifest_json"]
    parts = setup_handler["parts"]
    key_dir = setup_handler["key_dir"]

    is_valid, message, reassembled = handler.verify_contract(
        manifest_json=manifest_json,
        parts=parts,
        public_key_path=str(key_dir / "ed25519_public.pem")
    )

    assert is_valid is True, f"Valid flow should pass: {message}"
    assert reassembled is not None