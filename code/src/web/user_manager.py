"""
User Manager - Handles user registration, authentication, and contract management.
Simple JSON-based storage for demo purposes.
"""

import json
import os
import uuid
import hashlib
import secrets
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple


DATA_DIR = Path(__file__).resolve().parents[3] / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

USERS_FILE = DATA_DIR / "users.json"
CONTRACTS_FILE = DATA_DIR / "contracts.json"


def _hash_password(password: str, salt: str = None) -> tuple:
    """Hash a password with a salt using SHA-256 (for demo purposes)."""
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt, pw_hash.hex()


def _verify_password(password: str, salt: str, stored_hash: str) -> bool:
    """Verify a password against stored hash."""
    _, computed_hash = _hash_password(password, salt)
    return computed_hash == stored_hash


def _load_json(filepath: Path) -> dict:
    """Load JSON data from a file."""
    if filepath.exists():
        try:
            return json.loads(filepath.read_text(encoding='utf-8'))
        except (json.JSONDecodeError, Exception):
            return {}
    return {}


def _save_json(filepath: Path, data: dict) -> None:
    """Save JSON data to a file."""
    filepath.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')


def _generate_id() -> str:
    """Generate a unique ID."""
    return uuid.uuid4().hex[:12].upper()


# ===== User Management =====

def register_user(username: str, password: str, full_name: str,
                  account_type: str = "individual", email: str = "",
                  phone: str = "") -> Tuple[bool, str]:
    """
    Register a new user.
    
    Args:
        username: Unique username
        password: Password
        full_name: Full name
        account_type: "individual" or "business"
        email: Email address
        phone: Phone number
        
    Returns:
        Tuple[bool, str]: (success, message or user_id)
    """
    users = _load_json(USERS_FILE)
    
    if username in users:
        return False, "Username already exists"
    
    salt, pw_hash = _hash_password(password)
    user_id = _generate_id()
    
    users[username] = {
        "id": user_id,
        "username": username,
        "password_hash": pw_hash,
        "password_salt": salt,
        "full_name": full_name,
        "account_type": account_type,
        "email": email,
        "phone": phone,
        "created_at": datetime.now().isoformat(),
        "public_key_path": ""
    }
    
    _save_json(USERS_FILE, users)
    return True, user_id


def authenticate(username: str, password: str) -> Tuple[bool, Optional[dict]]:
    """
    Authenticate a user.
    
    Args:
        username: Username
        password: Password
        
    Returns:
        Tuple[bool, Optional[dict]]: (success, user_data or None)
    """
    users = _load_json(USERS_FILE)
    
    if username not in users:
        return False, None
    
    user = users[username]
    if _verify_password(password, user["password_salt"], user["password_hash"]):
        return True, user
    
    return False, None


def get_user(username: str) -> Optional[dict]:
    """Get user data by username."""
    users = _load_json(USERS_FILE)
    return users.get(username)


def get_user_by_id(user_id: str) -> Optional[dict]:
    """Get user data by user ID."""
    users = _load_json(USERS_FILE)
    for u in users.values():
        if u["id"] == user_id:
            return u
    return None


def get_all_users() -> List[dict]:
    """Get all registered users (excluding passwords)."""
    users = _load_json(USERS_FILE)
    result = []
    for u in users.values():
        result.append({
            "id": u["id"],
            "username": u["username"],
            "full_name": u["full_name"],
            "account_type": u["account_type"],
            "email": u["email"]
        })
    return result


def update_public_key(username: str, key_path: str) -> bool:
    """Update user's public key path."""
    users = _load_json(USERS_FILE)
    if username in users:
        users[username]["public_key_path"] = key_path
        _save_json(USERS_FILE, users)
        return True
    return False


# ===== Contract Management =====

def create_contract(title: str, content: str, sender_username: str,
                    recipient_usernames: List[str], num_parts: int = 3) -> Tuple[bool, str, Optional[dict]]:
    """
    Create a new contract.
    
    Args:
        title: Contract title
        content: Contract content
        sender_username: Username of sender
        recipient_usernames: List of recipient usernames
        num_parts: Number of parts to split into
        
    Returns:
        Tuple[bool, str, Optional[dict]]: (success, message, contract_data)
    """
    contracts = _load_json(CONTRACTS_FILE)
    
    contract_id = f"CTR-{_generate_id()}"
    
    contract = {
        "id": contract_id,
        "title": title,
        "content": content,
        "sender": sender_username,
        "recipients": recipient_usernames,
        "num_parts": num_parts,
        "status": "pending",  # pending, signed, verified
        "signed_parts": {},
        "verified_by": [],
        "created_at": datetime.now().isoformat(),
        "manifest": None,
        "parts": None
    }
    
    contracts[contract_id] = contract
    _save_json(CONTRACTS_FILE, contracts)
    
    return True, contract_id, contract


def get_contract(contract_id: str) -> Optional[dict]:
    """Get contract data by ID."""
    contracts = _load_json(CONTRACTS_FILE)
    return contracts.get(contract_id)


def get_contracts_for_user(username: str) -> Tuple[List[dict], List[dict]]:
    """
    Get contracts where user is sender or recipient.
    
    Returns:
        Tuple[List, List]: (sent_contracts, received_contracts)
    """
    contracts = _load_json(CONTRACTS_FILE)
    sent = []
    received = []
    
    for c in contracts.values():
        if c["sender"] == username:
            sent.append(c)
        if username in c.get("recipients", []):
            received.append(c)
    
    # Sort by created_at (newest first)
    sent.sort(key=lambda x: x["created_at"], reverse=True)
    received.sort(key=lambda x: x["created_at"], reverse=True)
    
    return sent, received


def update_contract_status(contract_id: str, status: str,
                           manifest: str = None, parts: list = None) -> bool:
    """Update contract status and signed data."""
    contracts = _load_json(CONTRACTS_FILE)
    if contract_id not in contracts:
        return False
    
    contracts[contract_id]["status"] = status
    if manifest:
        contracts[contract_id]["manifest"] = manifest
    if parts:
        contracts[contract_id]["parts"] = parts
    
    _save_json(CONTRACTS_FILE, contracts)
    return True


def delete_contract(contract_id: str) -> bool:
    """Delete a contract."""
    contracts = _load_json(CONTRACTS_FILE)
    if contract_id in contracts:
        del contracts[contract_id]
        _save_json(CONTRACTS_FILE, contracts)
        return True
    return False


# ===== Initialize sample users =====
def init_sample_users():
    """Create sample users for testing."""
    sample_users = [
        ("admin", "admin123", "Admin System", "individual", "admin@contract.com", "0901111111"),
        ("congty_abc", "abc123", "Công ty TNHH ABC", "business", "abc@company.com", "0902222222"),
        ("nguyen_van_a", "pass123", "Nguyễn Văn An", "individual", "an.nguyen@email.com", "0903333333"),
        ("tran_thi_b", "pass456", "Trần Thị Bình", "individual", "binh.tran@email.com", "0904444444"),
        ("le_van_c", "pass789", "Lê Văn Cường", "individual", "cuong.le@email.com", "0905555555"),
        ("pham_thi_d", "pass000", "Phạm Thị Dung", "individual", "dung.pham@email.com", "0906666666"),
        ("doanhnghiep_xyz", "xyz123", "Công ty CP XYZ", "business", "xyz@company.com", "0907777777"),
        ("hoang_van_e", "hoang123", "Hoàng Văn Em", "individual", "em.hoang@email.com", "0908888888"),
        ("vu_thi_f", "vu123", "Vũ Thị Phương", "individual", "phong.vu@email.com", "0909999999"),
        ("startup_tech", "tech123", "Startup Tech Solutions", "business", "tech@startup.com", "0910000000"),
        ("dang_van_g", "dang123", "Đặng Văn Giap", "individual", "giap.dang@email.com", "0911111111"),
        ("doanhnghiep_mnp", "mnp123", "Tập đoàn MNP", "business", "mnp@group.com", "0912222222"),
    ]
    
    users = _load_json(USERS_FILE)
    created = 0
    
    for username, password, name, acc_type, email, phone in sample_users:
        if username not in users:
            salt, pw_hash = _hash_password(password)
            user_id = _generate_id()
            users[username] = {
                "id": user_id,
                "username": username,
                "password_hash": pw_hash,
                "password_salt": salt,
                "full_name": name,
                "account_type": acc_type,
                "email": email,
                "phone": phone,
                "created_at": datetime.now().isoformat(),
                "public_key_path": ""
            }
            created += 1
    
    _save_json(USERS_FILE, users)
    return created


# Initialize on import
init_sample_users()