"""
Test: Valid Flow - Tests the complete contract signing and verification flow.

Verifies:
- Key generation works for Ed25519 and RSA-PSS
- Contract splitting produces the correct number of parts
- Each part has required fields (part_id, contract_id, sequence_number, hash, signature)
- Manifest is properly signed and validated
- Contract reassembly produces the original text
"""

import pytest
import json
import tempfile
import os
from pathlib import Path

# Add src to path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.crypto.crypto_manager import CryptoManager, KeyManager
from src.server.contract_handler import ContractHandler
from src.server.manifest import ManifestManager
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
def temp_key_dir(tmp_path):
    """Create a temporary key directory and set it as the default."""
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    # Point DEFAULT_KEY_DIR to temp
    import src.crypto.crypto_manager as cm
    original = cm.KeyManager.DEFAULT_KEY_DIR
    cm.KeyManager.DEFAULT_KEY_DIR = key_dir
    yield key_dir
    cm.KeyManager.DEFAULT_KEY_DIR = original


@pytest.fixture
def ed25519_keys(temp_key_dir):
    """Generate Ed25519 keys and save to temporary default directory."""
    priv_pem, pub_pem = KeyManager.generate_ed25519_key_pair()
    priv_path = temp_key_dir / "ed25519_private.pem"
    pub_path = temp_key_dir / "ed25519_public.pem"
    KeyManager.save_key_to_file(priv_pem, str(priv_path))
    KeyManager.save_key_to_file(pub_pem, str(pub_path))
    return str(priv_path), str(pub_path)


@pytest.fixture
def rsa_pss_keys(temp_key_dir):
    """Generate RSA-PSS keys and save to temporary default directory."""
    priv_pem, pub_pem = KeyManager.generate_rsa_pss_key_pair()
    priv_path = temp_key_dir / "rsa-pss_private.pem"
    pub_path = temp_key_dir / "rsa-pss_public.pem"
    KeyManager.save_key_to_file(priv_pem, str(priv_path))
    KeyManager.save_key_to_file(pub_pem, str(pub_path))
    return str(priv_path), str(pub_path)


def test_key_generation_ed25519():
    """Test that Ed25519 key generation works."""
    priv_pem, pub_pem = KeyManager.generate_ed25519_key_pair()
    assert priv_pem.startswith(b'-----BEGIN PRIVATE KEY-----')
    assert pub_pem.startswith(b'-----BEGIN PUBLIC KEY-----')

    # Test loading
    priv_key = KeyManager.load_key_from_bytes(priv_pem)
    pub_key = KeyManager.load_key_from_bytes(pub_pem)
    assert priv_key is not None
    assert pub_key is not None


def test_key_generation_rsa_pss():
    """Test that RSA-PSS key generation works."""
    priv_pem, pub_pem = KeyManager.generate_rsa_pss_key_pair()
    assert priv_pem.startswith(b'-----BEGIN PRIVATE KEY-----')
    assert pub_pem.startswith(b'-----BEGIN PUBLIC KEY-----')

    # Test loading
    priv_key = KeyManager.load_key_from_bytes(priv_pem)
    pub_key = KeyManager.load_key_from_bytes(pub_pem)
    assert priv_key is not None
    assert pub_key is not None


def test_sign_and_verify_part_ed25519(ed25519_keys):
    """Test signing and verifying a single contract part with Ed25519."""
    priv_path, pub_path = ed25519_keys
    priv_key = KeyManager.load_private_key(priv_path)
    pub_key = KeyManager.load_public_key(pub_path)

    crypto = CryptoManager(algorithm="ed25519")

    part = crypto.sign_part(
        part_id="PART-001",
        contract_id="TEST-CONTRACT",
        sequence_number=1,
        content="This is test content for a contract part.",
        private_key=priv_key
    )

    # Check part structure
    assert part["part_id"] == "PART-001"
    assert part["contract_id"] == "TEST-CONTRACT"
    assert part["sequence_number"] == 1
    assert "hash" in part
    assert "signature" in part
    assert part["algorithm"] == "ed25519"

    # Verify
    result = crypto.verify_part(part, pub_key)
    assert result is True


def test_sign_and_verify_part_rsa_pss(rsa_pss_keys):
    """Test signing and verifying a single contract part with RSA-PSS."""
    priv_path, pub_path = rsa_pss_keys
    priv_key = KeyManager.load_private_key(priv_path)
    pub_key = KeyManager.load_public_key(pub_path)

    crypto = CryptoManager(algorithm="rsa-pss")

    part = crypto.sign_part(
        part_id="PART-001",
        contract_id="TEST-CONTRACT",
        sequence_number=1,
        content="This is test content for a contract part.",
        private_key=priv_key
    )

    assert part["algorithm"] == "rsa-pss"

    # Verify
    result = crypto.verify_part(part, pub_key)
    assert result is True


def test_full_contract_flow_ed25519(ed25519_keys, tmp_path):
    """Test the complete contract signing and verification flow with Ed25519."""
    priv_path, pub_path = ed25519_keys
    key_dir = Path(priv_path).parent

    crypto = CryptoManager(algorithm="ed25519")
    logger = SecurityLogger(log_dir=str(tmp_path / "logs"))
    handler = ContractHandler(crypto_manager=crypto, logger=logger)

    # Split and sign contract
    manifest_json, parts = handler.split_contract(
        contract_text=SAMPLE_CONTRACT,
        contract_id="TEST-FLOW",
        num_parts=3
    )

    assert len(parts) == 3
    assert parts[0]["sequence_number"] == 1
    assert parts[1]["sequence_number"] == 2
    assert parts[2]["sequence_number"] == 3

    # Verify contract
    is_valid, message, reassembled = handler.verify_contract(
        manifest_json=manifest_json,
        parts=parts,
        public_key_path=str(key_dir / "ed25519_public.pem")
    )

    assert is_valid is True
    assert reassembled is not None

    # Check reassembled contract matches original
    normalized_original = SAMPLE_CONTRACT.strip()
    normalized_reassembled = reassembled.strip()
    assert normalized_reassembled == normalized_original


def test_full_contract_flow_rsa_pss(rsa_pss_keys, tmp_path):
    """Test the complete contract signing and verification flow with RSA-PSS."""
    priv_path, pub_path = rsa_pss_keys
    key_dir = Path(priv_path).parent

    crypto = CryptoManager(algorithm="rsa-pss")
    logger = SecurityLogger(log_dir=str(tmp_path / "logs"))
    handler = ContractHandler(crypto_manager=crypto, logger=logger)

    manifest_json, parts = handler.split_contract(
        contract_text=SAMPLE_CONTRACT,
        contract_id="TEST-RSA-FLOW",
        num_parts=3
    )

    assert len(parts) == 3

    is_valid, message, reassembled = handler.verify_contract(
        manifest_json=manifest_json,
        parts=parts,
        public_key_path=str(key_dir / "rsa-pss_public.pem")
    )

    assert is_valid is True
    assert reassembled is not None


def test_manifest_sign_and_verify(ed25519_keys, tmp_path):
    """Test manifest creation and validation."""
    priv_path, pub_path = ed25519_keys
    priv_key = KeyManager.load_private_key(priv_path)
    pub_key = KeyManager.load_public_key(pub_path)

    crypto = CryptoManager(algorithm="ed25519")
    logger = SecurityLogger(log_dir=str(tmp_path / "logs"))
    manifest_mgr = ManifestManager(crypto_manager=crypto, logger=logger)

    # Create sample parts
    parts = [
        {"part_id": "PART-001", "sequence_number": 1, "hash": "abc"},
        {"part_id": "PART-002", "sequence_number": 2, "hash": "def"},
    ]

    manifest = manifest_mgr.create_manifest("TEST-MANIFEST", parts)

    assert manifest["contract_id"] == "TEST-MANIFEST"
    assert manifest["total_parts"] == 2
    assert "manifest_signature" in manifest

    # Validate manifest
    is_valid, message = manifest_mgr.validate_manifest(manifest, str(pub_path))
    assert is_valid is True


def test_contract_part_fields(ed25519_keys):
    """Test that each contract part has all required fields."""
    priv_path, _ = ed25519_keys
    priv_key = KeyManager.load_private_key(priv_path)

    crypto = CryptoManager(algorithm="ed25519")

    part = crypto.sign_part(
        part_id="PART-001",
        contract_id="TEST-REQUIRED-FIELDS",
        sequence_number=1,
        content="Required fields test content.",
        private_key=priv_key
    )

    required_fields = ["part_id", "contract_id", "sequence_number",
                       "content", "hash", "signature", "algorithm"]
    for field in required_fields:
        assert field in part, f"Missing required field: {field}"


def test_contract_handler_without_replay(tmp_path):
    """Test contract handler can work without replay protection."""
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

    try:
        crypto = CryptoManager(algorithm="ed25519")
        logger = SecurityLogger(log_dir=str(tmp_path / "logs"))
        handler = ContractHandler(crypto_manager=crypto, logger=logger,
                                  replay_protection=None)

        manifest_json, parts = handler.split_contract(
            contract_text=SAMPLE_CONTRACT,
            contract_id="NO-REPLAY-TEST",
            num_parts=2
        )

        assert len(parts) == 2

        is_valid, message, reassembled = handler.verify_contract(
            manifest_json=manifest_json,
            parts=parts,
            public_key_path=str(key_dir / "ed25519_public.pem")
        )

        assert is_valid is True
    finally:
        cm.KeyManager.DEFAULT_KEY_DIR = original