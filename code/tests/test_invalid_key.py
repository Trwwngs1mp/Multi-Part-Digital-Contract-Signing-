"""
Test: Invalid Key - Tests that using the wrong key fails verification.

Verifies:
- Verification with wrong public key fails
- Verification with wrong algorithm fails
- Tampered signature is detected
- Missing key file handling
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
"""


@pytest.fixture
def setup_two_key_pairs(tmp_path):
    """Set up two different key pairs for testing wrong key detection."""
    # Key pair A (sender)
    key_dir_a = tmp_path / "keys_a"
    key_dir_a.mkdir()
    priv_a, pub_a = KeyManager.generate_ed25519_key_pair()
    KeyManager.save_key_to_file(priv_a, str(key_dir_a / "ed25519_private.pem"))
    KeyManager.save_key_to_file(pub_a, str(key_dir_a / "ed25519_public.pem"))

    # Key pair B (attacker)
    key_dir_b = tmp_path / "keys_b"
    key_dir_b.mkdir()
    priv_b, pub_b = KeyManager.generate_ed25519_key_pair()
    KeyManager.save_key_to_file(pub_b, str(key_dir_b / "ed25519_public.pem"))

    # Point default key dir to key A
    import src.crypto.crypto_manager as cm
    original_default = cm.KeyManager.DEFAULT_KEY_DIR
    cm.KeyManager.DEFAULT_KEY_DIR = key_dir_a

    crypto = CryptoManager(algorithm="ed25519")
    logger = SecurityLogger(log_dir=str(tmp_path / "logs"))
    handler = ContractHandler(crypto_manager=crypto, logger=logger)

    # Sign contract with key A
    manifest_json, parts = handler.split_contract(
        contract_text=SAMPLE_CONTRACT,
        contract_id="WRONG-KEY-TEST",
        num_parts=2
    )

    yield {
        "handler": handler,
        "manifest_json": manifest_json,
        "parts": parts,
        "key_dir_a": key_dir_a,
        "key_dir_b": key_dir_b,
        "original_default": original_default
    }

    # Restore
    import src.crypto.crypto_manager as cm
    cm.KeyManager.DEFAULT_KEY_DIR = original_default


def test_wrong_public_key_fails(setup_two_key_pairs):
    """Test that verification with the wrong public key fails."""
    data = setup_two_key_pairs
    handler = data["handler"]
    manifest_json = data["manifest_json"]
    parts = data["parts"]
    key_dir_b = data["key_dir_b"]

    # Verify with key B's public key (wrong key)
    is_valid, message, reassembled = handler.verify_contract(
        manifest_json=manifest_json,
        parts=parts,
        public_key_path=str(key_dir_b / "ed25519_public.pem")
    )

    assert is_valid is False, "Verification should fail with wrong public key"


def test_correct_public_key_succeeds(setup_two_key_pairs):
    """Test that verification with the correct public key succeeds."""
    data = setup_two_key_pairs
    handler = data["handler"]
    manifest_json = data["manifest_json"]
    parts = data["parts"]
    key_dir_a = data["key_dir_a"]

    is_valid, message, reassembled = handler.verify_contract(
        manifest_json=manifest_json,
        parts=parts,
        public_key_path=str(key_dir_a / "ed25519_public.pem")
    )

    assert is_valid is True, f"Verification should succeed with correct key: {message}"


def test_tampered_signature_fails():
    """Test that a tampered signature is detected."""
    priv_pem, pub_pem = KeyManager.generate_ed25519_key_pair()
    priv_key = KeyManager.load_key_from_bytes(priv_pem)
    pub_key = KeyManager.load_key_from_bytes(pub_pem)

    crypto = CryptoManager(algorithm="ed25519")

    part = crypto.sign_part(
        part_id="PART-001",
        contract_id="TAMPER-SIG",
        sequence_number=1,
        content="Test content for signature tampering.",
        private_key=priv_key
    )

    # Tamper with the signature
    original_sig = part["signature"]
    part["signature"] = "0" * len(original_sig)

    # Verification should fail
    result = crypto.verify_part(part, pub_key)
    assert result is False, "Verification should fail with tampered signature"


def test_empty_signature_fails():
    """Test that an empty/zero signature is detected as invalid."""
    priv_pem, pub_pem = KeyManager.generate_ed25519_key_pair()
    priv_key = KeyManager.load_key_from_bytes(priv_pem)
    pub_key = KeyManager.load_key_from_bytes(pub_pem)

    crypto = CryptoManager(algorithm="ed25519")

    part = crypto.sign_part(
        part_id="PART-001",
        contract_id="EMPTY-SIG",
        sequence_number=1,
        content="Test content.",
        private_key=priv_key
    )

    # Set empty signature
    part["signature"] = ""

    # Should return False (invalid signature) rather than raising an exception
    result = crypto.verify_part(part, pub_key)
    assert result is False, "Empty signature should be detected as invalid"


def test_wrong_key_type_fails():
    """Test that using an RSA key to verify Ed25519 signature fails."""
    # Generate Ed25519 keys and sign
    ed_priv, ed_pub = KeyManager.generate_ed25519_key_pair()
    ed_priv_key = KeyManager.load_key_from_bytes(ed_priv)
    ed_pub_key = KeyManager.load_key_from_bytes(ed_pub)

    crypto_ed = CryptoManager(algorithm="ed25519")
    part = crypto_ed.sign_part(
        part_id="PART-001",
        contract_id="KEY-TYPE",
        sequence_number=1,
        content="Test key type mismatch.",
        private_key=ed_priv_key
    )

    # Generate RSA key pair
    rsa_priv, rsa_pub = KeyManager.generate_rsa_pss_key_pair()
    rsa_pub_key = KeyManager.load_key_from_bytes(rsa_pub)

    # Verify Ed25519 part with RSA public key (using Ed25519 crypto manager)
    # This should fail
    result = crypto_ed.verify_part(part, rsa_pub_key)
    assert result is False, "Cross-algorithm verification should fail"


def test_rsa_wrong_key_fails():
    """Test that RSA-PSS with wrong key fails."""
    priv_a, pub_a = KeyManager.generate_rsa_pss_key_pair()
    priv_b, pub_b = KeyManager.generate_rsa_pss_key_pair()

    priv_a_key = KeyManager.load_key_from_bytes(priv_a)
    pub_b_key = KeyManager.load_key_from_bytes(pub_b)

    crypto = CryptoManager(algorithm="rsa-pss")

    part = crypto.sign_part(
        part_id="PART-001",
        contract_id="RSA-WRONG",
        sequence_number=1,
        content="RSA wrong key test.",
        private_key=priv_a_key
    )

    result = crypto.verify_part(part, pub_b_key)
    assert result is False, "RSA verification with wrong key should fail"


def test_missing_key_file():
    """Test that missing key file is handled gracefully."""
    with pytest.raises((ValueError, FileNotFoundError)):
        KeyManager.load_public_key("C:/nonexistent/path/key.pem")