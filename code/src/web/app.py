#!/usr/bin/env python3
"""
Web Application - Multi-Part Digital Contract Signing
Modern dark-themed UI for signing and verifying contracts with user management.
"""

import sys, os, json, tempfile, shutil
from pathlib import Path
from flask import Flask, render_template, request, jsonify, session
from functools import wraps

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.crypto.crypto_manager import CryptoManager, KeyManager
from src.server.contract_handler import ContractHandler
from src.server.manifest import ManifestManager
from src.utils.logger import SecurityLogger
from src.utils.replay_protection import ReplayProtection
from src.web import user_manager as um

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32).hex()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

TEMP_DIR = Path(tempfile.gettempdir()) / "contract_signing_web"
TEMP_DIR.mkdir(parents=True, exist_ok=True)


# ===== Auth Decorator =====
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({"error": "Not authenticated"}), 401
        return f(*args, **kwargs)
    return decorated_function


# ===== Auth Routes =====

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    full_name = data.get('full_name', '').strip()
    account_type = data.get('account_type', 'individual')
    email = data.get('email', '').strip()
    phone = data.get('phone', '').strip()

    if not username or not password or not full_name:
        return jsonify({"success": False, "error": "Missing required fields"}), 400

    if len(username) < 3:
        return jsonify({"success": False, "error": "Username must be at least 3 characters"}), 400

    if len(password) < 4:
        return jsonify({"success": False, "error": "Password must be at least 4 characters"}), 400

    success, result = um.register_user(username, password, full_name, account_type, email, phone)
    
    if success:
        # Auto login after registration
        session['username'] = username
        user = um.get_user(username)
        return jsonify({
            "success": True,
            "user": {
                "username": user["username"],
                "full_name": user["full_name"],
                "account_type": user["account_type"],
                "id": user["id"]
            }
        })
    else:
        return jsonify({"success": False, "error": result}), 400


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({"success": False, "error": "Missing username or password"}), 400

    success, user = um.authenticate(username, password)
    
    if success:
        session['username'] = username
        session['user_id'] = user['id']
        return jsonify({
            "success": True,
            "user": {
                "username": user["username"],
                "full_name": user["full_name"],
                "account_type": user["account_type"],
                "email": user.get("email", ""),
                "phone": user.get("phone", ""),
                "id": user["id"]
            }
        })
    else:
        return jsonify({"success": False, "error": "Invalid username or password"}), 401


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True})


@app.route('/api/auth/session', methods=['GET'])
def get_session():
    if 'username' in session:
        user = um.get_user(session['username'])
        if user:
            return jsonify({
                "authenticated": True,
                "user": {
                    "username": user["username"],
                    "full_name": user["full_name"],
                    "account_type": user["account_type"],
                    "email": user.get("email", ""),
                    "phone": user.get("phone", ""),
                    "id": user["id"]
                }
            })
    return jsonify({"authenticated": False})


# ===== User Management Routes =====

@app.route('/api/users/list', methods=['GET'])
@login_required
def list_users():
    users = um.get_all_users()
    current = session['username']
    # Filter out current user
    others = [u for u in users if u['username'] != current]
    return jsonify({"success": True, "users": others})


@app.route('/api/users/profile', methods=['GET'])
@login_required
def get_profile():
    user = um.get_user(session['username'])
    if user:
        return jsonify({
            "success": True,
            "user": {
                "username": user["username"],
                "full_name": user["full_name"],
                "account_type": user["account_type"],
                "email": user.get("email", ""),
                "phone": user.get("phone", ""),
                "id": user["id"],
                "created_at": user.get("created_at", ""),
                "public_key_path": user.get("public_key_path", "")
            }
        })
    return jsonify({"success": False, "error": "User not found"}), 404


# ===== Key Management Routes =====

@app.route('/api/keys/status', methods=['GET'])
@login_required
def key_status():
    key_dir = KeyManager.DEFAULT_KEY_DIR
    ed25519_exists = (key_dir / "ed25519_private.pem").exists()
    rsa_exists = (key_dir / "rsa-pss_private.pem").exists()
    has_keys = ed25519_exists or rsa_exists

    keys_info = []
    if ed25519_exists:
        pub = (key_dir / "ed25519_public.pem").read_text()
        keys_info.append({"algorithm": "Ed25519", "status": "active", "public_key": pub[-80:].strip()})
    if rsa_exists:
        pub = (key_dir / "rsa-pss_public.pem").read_text()
        keys_info.append({"algorithm": "RSA-PSS (2048)", "status": "active", "public_key": pub[-80:].strip()})

    return jsonify({"has_keys": has_keys, "keys": keys_info, "key_dir": str(key_dir)})


@app.route('/api/keys/generate', methods=['POST'])
@login_required
def generate_keys():
    data = request.get_json()
    algorithm = data.get('algorithm', 'ed25519')

    try:
        key_dir = KeyManager.DEFAULT_KEY_DIR
        key_dir.mkdir(parents=True, exist_ok=True)

        if algorithm == "ed25519":
            priv, pub = KeyManager.generate_ed25519_key_pair()
        else:
            priv, pub = KeyManager.generate_rsa_pss_key_pair()

        KeyManager.save_key_to_file(priv, str(key_dir / f"{algorithm}_private.pem"))
        KeyManager.save_key_to_file(pub, str(key_dir / f"{algorithm}_public.pem"))

        # Update user's public key path
        um.update_public_key(session['username'], str(key_dir / f"{algorithm}_public.pem"))

        return jsonify({
            "success": True,
            "algorithm": algorithm,
            "message": f"{'Ed25519' if algorithm == 'ed25519' else 'RSA-PSS'} keys generated successfully"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ===== Contract Management Routes =====

@app.route('/api/contracts/create', methods=['POST'])
@login_required
def create_contract():
    data = request.get_json()
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()
    recipients = data.get('recipients', [])
    num_parts = data.get('num_parts', 3)

    if not title or not content:
        return jsonify({"success": False, "error": "Missing title or content"}), 400
    if not recipients:
        return jsonify({"success": False, "error": "Please select at least one recipient"}), 400

    success, contract_id, contract = um.create_contract(
        title=title,
        content=content,
        sender_username=session['username'],
        recipient_usernames=recipients,
        num_parts=num_parts
    )

    if success:
        return jsonify({"success": True, "contract": contract})
    else:
        return jsonify({"success": False, "error": "Failed to create contract"}), 500


@app.route('/api/contracts/list', methods=['GET'])
@login_required
def list_contracts():
    sent, received = um.get_contracts_for_user(session['username'])
    return jsonify({
        "success": True,
        "sent": sent,
        "received": received
    })


@app.route('/api/contracts/<contract_id>', methods=['GET'])
@login_required
def get_contract_detail(contract_id):
    contract = um.get_contract(contract_id)
    if not contract:
        return jsonify({"success": False, "error": "Contract not found"}), 404
    return jsonify({"success": True, "contract": contract})


@app.route('/api/contracts/<contract_id>/sign', methods=['POST'])
@login_required
def sign_contract(contract_id):
    """Sign a contract and create manifest."""
    contract = um.get_contract(contract_id)
    if not contract:
        return jsonify({"success": False, "error": "Contract not found"}), 404

    data = request.get_json()
    algorithm = data.get('algorithm', 'ed25519')

    try:
        # Check keys
        key_dir = KeyManager.DEFAULT_KEY_DIR
        key_path = key_dir / f"{algorithm}_private.pem"
        if not key_path.exists():
            return jsonify({"success": False, "error": "No keys found. Generate keys first."}), 400

        crypto = CryptoManager(algorithm=algorithm)
        logger = SecurityLogger(log_dir=str(TEMP_DIR / "logs"))
        handler = ContractHandler(crypto_manager=crypto, logger=logger)

        manifest_json, parts = handler.split_contract(
            contract_text=contract['content'],
            contract_id=contract['id'],
            num_parts=contract['num_parts']
        )

        # Update contract status
        um.update_contract_status(contract_id, "signed", manifest_json, parts)

        manifest = json.loads(manifest_json)
        parts_output = []
        for p in parts:
            parts_output.append({
                "part_id": p["part_id"],
                "sequence_number": p["sequence_number"],
                "hash": p["hash"][:16] + "...",
                "signature": p["signature"][:24] + "...",
                "content_preview": p["content"][:80] + ("..." if len(p["content"]) > 80 else ""),
                "algorithm": p["algorithm"]
            })

        return jsonify({
            "success": True,
            "contract_id": contract['id'],
            "total_parts": len(parts),
            "parts": parts_output,
            "manifest": manifest_json,
            "algorithm": algorithm
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/contracts/<contract_id>/verify', methods=['POST'])
@login_required
def verify_contract(contract_id):
    """Verify a signed contract."""
    contract = um.get_contract(contract_id)
    if not contract:
        return jsonify({"success": False, "error": "Contract not found"}), 404

    if not contract.get('manifest') or not contract.get('parts'):
        return jsonify({"success": False, "error": "Contract has not been signed yet"}), 400

    data = request.get_json()
    algorithm = data.get('algorithm', 'ed25519')

    try:
        crypto = CryptoManager(algorithm=algorithm)
        logger = SecurityLogger(log_dir=str(TEMP_DIR / "logs"))
        handler = ContractHandler(crypto_manager=crypto, logger=logger)

        parts = contract['parts']
        manifest_json = contract['manifest']

        key_dir = KeyManager.DEFAULT_KEY_DIR
        pub_key_path = key_dir / f"{algorithm}_public.pem"

        if not pub_key_path.exists():
            return jsonify({"success": False, "error": "No public key found"}), 400

        is_valid, message, reassembled = handler.verify_contract(
            manifest_json=manifest_json,
            parts=parts,
            public_key_path=str(pub_key_path)
        )

        if is_valid:
            um.update_contract_status(contract_id, "verified")

        return jsonify({
            "success": True,
            "is_valid": is_valid,
            "message": message,
            "reassembled_contract": reassembled
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/contracts/<contract_id>/delete', methods=['DELETE'])
@login_required
def delete_contract(contract_id):
    contract = um.get_contract(contract_id)
    if not contract:
        return jsonify({"success": False, "error": "Contract not found"}), 404
    if contract['sender'] != session['username']:
        return jsonify({"success": False, "error": "You can only delete your own contracts"}), 403
    
    um.delete_contract(contract_id)
    return jsonify({"success": True})


@app.route('/api/contracts/<contract_id>/tamper', methods=['POST'])
@login_required
def tamper_contract(contract_id):
    """Simulate tampering on a signed contract."""
    contract = um.get_contract(contract_id)
    if not contract or not contract.get('parts'):
        return jsonify({"success": False, "error": "Contract not found or not signed"}), 404

    data = request.get_json()
    tamper_type = data.get('tamper_type', 'modify')
    part_index = data.get('part_index', 0)

    parts = list(contract['parts'])
    tamper_desc = ""

    if tamper_type == 'modify':
        parts[part_index]["content"] = "⚠️ NỘI DUNG ĐÃ BỊ THAY ĐỔI BỞI KẺ TẤN CÔNG! ⚠️"
        tamper_desc = f"Modified content of {parts[part_index]['part_id']}"
    elif tamper_type == 'remove':
        removed = parts.pop(part_index)
        tamper_desc = f"Removed {removed['part_id']}"
    elif tamper_type == 'reorder':
        if len(parts) >= 2:
            parts[0], parts[-1] = parts[-1], parts[0]
            tamper_desc = f"Reversed order of parts"
    elif tamper_type == 'hash':
        parts[part_index]["hash"] = "0" * 64
        tamper_desc = f"Corrupted hash of {parts[part_index]['part_id']}"
    elif tamper_type == 'signature':
        parts[part_index]["signature"] = "0" * 128
        tamper_desc = f"Corrupted signature of {parts[part_index]['part_id']}"

    return jsonify({
        "success": True,
        "parts": parts,
        "manifest": contract['manifest'],
        "tamper_desc": tamper_desc,
        "tamper_type": tamper_type,
        "algorithm": contract.get('algorithm', 'ed25519')
    })


@app.route('/api/test/run', methods=['POST'])
@login_required
def run_tests():
    import pytest
    try:
        test_dir = Path(__file__).resolve().parents[2] / "tests"
        result = pytest.main([str(test_dir), "-v", "--tb=line", "--no-header", "-q"])
        passed = result == 0
        return jsonify({"success": True, "passed": passed, "exit_code": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/sample/contract', methods=['GET'])
def get_sample_contract():
    sample = """HỢP ĐỒNG HỢP TÁC KINH DOANH SỐ 2024/HD-HT

PHẦN 1: THÔNG TIN CÁC BÊN

Bên A: CÔNG TY TNHH GIẢI PHÁP SỐ ABC
Địa chỉ: 123 Nguyễn Huệ, Quận 1, TP. Hồ Chí Minh
Mã số thuế: 0123456789

Bên B: CÔNG TY CỔ PHẦN CÔNG NGHỆ XYZ
Địa chỉ: 456 Lê Lợi, Quận 3, TP. Hồ Chí Minh
Mã số thuế: 0987654321

PHẦN 2: MỤC ĐÍCH VÀ PHẠM VI HỢP TÁC
Hai bên cùng hợp tác phát triển dự án "Chuyển đổi số toàn diện" cho các doanh nghiệp vừa và nhỏ tại khu vực Đông Nam Bộ.

PHẦN 3: GIÁ TRỊ HỢP ĐỒNG
Tổng giá trị hợp đồng: 15.000.000.000 VNĐ (Mười lăm tỷ đồng)

PHẦN 4: HIỆU LỰC
Hợp đồng có hiệu lực từ ngày 01/01/2025 đến ngày 31/12/2027 (03 năm).

PHẦN 5: ĐIỀU KHOẢN CHUNG
Các bên cam kết bảo mật mọi thông tin. Mọi tranh chấp được giải quyết tại Tòa án Nhân dân TP. Hồ Chí Minh."""

    return jsonify({"success": True, "contract": sample})


if __name__ == '__main__':
    print("=" * 60)
    print("  Multi-Part Digital Contract Signing - Web UI")
    print("  Server: http://localhost:5000")
    print("  Sample accounts initialized!")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)