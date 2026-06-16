#!/usr/bin/env python3
"""
Web Application - Multi-Part Digital Contract Signing
Modern dark-themed UI with user management, auth, and ECDSA/RSA-PSS/Ed25519 support.
"""

import sys, os, json, tempfile
from pathlib import Path
from flask import Flask, render_template, request, jsonify, session
from functools import wraps

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.crypto.crypto_manager import CryptoManager, KeyManager
from src.server.contract_handler import ContractHandler
from src.utils.logger import SecurityLogger
from src.web import user_manager as um

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32).hex()
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB max upload

TEMP_DIR = Path(tempfile.gettempdir()) / "contract_signing_web"
TEMP_DIR.mkdir(parents=True, exist_ok=True)

UPLOAD_DIR = TEMP_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return jsonify({"error": "Not authenticated"}), 401
        return f(*args, **kwargs)
    return decorated


ALGORITHM_MAP = {
    "ed25519": ("Ed25519", lambda: KeyManager.generate_ed25519_key_pair()),
    "rsa-pss": ("RSA-PSS 2048", lambda: KeyManager.generate_rsa_pss_key_pair()),
    "ecdsa": ("ECDSA P-256", lambda: KeyManager.generate_ecdsa_key_pair()),
}


# ===== Auth Routes =====

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
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
            session['username'] = username
            user_data = um.get_user(username)
            if not user_data:
                return jsonify({"success": False, "error": "Account created but failed to load profile"}), 500
            return jsonify({"success": True, "user": {"username": user_data["username"], "full_name": user_data["full_name"], "account_type": user_data["account_type"], "id": user_data["id"]}})
        else:
            return jsonify({"success": False, "error": result}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Server error: {str(e)}"}), 500


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
        return jsonify({"success": True, "user": {"username": user["username"], "full_name": user["full_name"], "account_type": user["account_type"], "email": user.get("email", ""), "phone": user.get("phone", ""), "id": user["id"]}})
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
            return jsonify({"authenticated": True, "user": {"username": user["username"], "full_name": user["full_name"], "account_type": user["account_type"], "email": user.get("email", ""), "phone": user.get("phone", ""), "id": user["id"]}})
    return jsonify({"authenticated": False})


# ===== User Routes =====

@app.route('/api/users/list', methods=['GET'])
@login_required
def list_users():
    users = um.get_all_users()
    current = session['username']
    return jsonify({"success": True, "users": [u for u in users if u['username'] != current]})


@app.route('/api/users/profile', methods=['GET'])
@login_required
def get_profile():
    user = um.get_user(session['username'])
    if user:
        return jsonify({"success": True, "user": user})
    return jsonify({"success": False, "error": "User not found"}), 404


# ===== Key Routes =====

@app.route('/api/keys/status', methods=['GET'])
@login_required
def key_status():
    key_dir = KeyManager.DEFAULT_KEY_DIR
    keys_info = []
    for algo_key, (algo_name, _) in ALGORITHM_MAP.items():
        key_file = key_dir / f"{algo_key}_public.pem"
        if key_file.exists():
            pub = key_file.read_text()
            keys_info.append({"algorithm": algo_name, "key": algo_key, "status": "active", "public_key": pub[-80:].strip()})
    return jsonify({"has_keys": len(keys_info) > 0, "keys": keys_info, "key_dir": str(key_dir)})


@app.route('/api/keys/generate', methods=['POST'])
@login_required
def generate_keys():
    data = request.get_json()
    algorithm = data.get('algorithm', 'ed25519')
    if algorithm not in ALGORITHM_MAP:
        return jsonify({"success": False, "error": f"Unsupported algorithm: {algorithm}"}), 400
    try:
        key_dir = KeyManager.DEFAULT_KEY_DIR
        key_dir.mkdir(parents=True, exist_ok=True)
        algo_name, gen_func = ALGORITHM_MAP[algorithm]
        priv, pub = gen_func()
        KeyManager.save_key_to_file(priv, str(key_dir / f"{algorithm}_private.pem"))
        KeyManager.save_key_to_file(pub, str(key_dir / f"{algorithm}_public.pem"))
        um.update_public_key(session['username'], str(key_dir / f"{algorithm}_public.pem"))
        return jsonify({"success": True, "algorithm": algorithm, "message": f"{algo_name} keys generated successfully"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ===== File Upload =====

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "No file selected"}), 400

    try:
        content = file.read().decode('utf-8')
        filename = file.filename
        return jsonify({"success": True, "content": content, "filename": filename})
    except UnicodeDecodeError:
        return jsonify({"success": False, "error": "File must be in UTF-8 text format"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ===== Contract Routes =====

def get_signer(algorithm):
    key_dir = KeyManager.DEFAULT_KEY_DIR
    key_path = key_dir / f"{algorithm}_private.pem"
    pub_path = key_dir / f"{algorithm}_public.pem"
    if not key_path.exists():
        raise FileNotFoundError(f"No {algorithm} keys found. Generate keys first.")
    crypto = CryptoManager(algorithm=algorithm)
    logger = SecurityLogger(log_dir=str(TEMP_DIR / "logs"))
    handler = ContractHandler(crypto_manager=crypto, logger=logger)
    return crypto, handler, str(pub_path)


@app.route('/api/contracts/create', methods=['POST'])
@login_required
def create_contract():
    data = request.get_json()
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()
    recipients = data.get('recipients', [])
    num_parts = data.get('num_parts', 3)
    filename = data.get('filename', '')
    if not title or not content:
        return jsonify({"success": False, "error": "Missing title or content"}), 400
    if not recipients:
        return jsonify({"success": False, "error": "Select at least one recipient"}), 400
    success, contract_id, contract = um.create_contract(
        title=title, content=content, sender_username=session['username'],
        recipient_usernames=recipients, num_parts=num_parts, filename=filename
    )
    if success:
        return jsonify({"success": True, "contract": contract})
    return jsonify({"success": False, "error": "Failed to create contract"}), 500


@app.route('/api/contracts/list', methods=['GET'])
@login_required
def list_contracts():
    sent, received = um.get_contracts_for_user(session['username'])
    return jsonify({"success": True, "sent": sent, "received": received})


@app.route('/api/contracts/<contract_id>', methods=['GET'])
@login_required
def get_contract(contract_id):
    contract = um.get_contract(contract_id)
    if not contract:
        return jsonify({"success": False, "error": "Contract not found"}), 404
    return jsonify({"success": True, "contract": contract})


@app.route('/api/contracts/<contract_id>/sign', methods=['POST'])
@login_required
def sign_contract(contract_id):
    contract = um.get_contract(contract_id)
    if not contract:
        return jsonify({"success": False, "error": "Contract not found"}), 404
    if contract['sender'] != session['username']:
        return jsonify({"success": False, "error": "Only the sender can sign this contract"}), 403
    data = request.get_json()
    algorithm = data.get('algorithm', 'ed25519')
    try:
        crypto, handler, pub_path = get_signer(algorithm)
        manifest_json, parts = handler.split_contract(
            contract_text=contract['content'], contract_id=contract['id'], num_parts=contract['num_parts']
        )
        um.update_contract_status(contract_id, "signed", manifest_json, parts)
        manifest = json.loads(manifest_json)
        parts_output = []
        for p in parts:
            parts_output.append({
                "part_id": p["part_id"], "sequence_number": p["sequence_number"],
                "hash": p["hash"][:16] + "...", "signature": p["signature"][:24] + "...",
                "content_preview": p["content"][:80] + ("..." if len(p["content"]) > 80 else ""),
                "algorithm": p["algorithm"]
            })
        return jsonify({"success": True, "contract_id": contract['id'], "total_parts": len(parts), "parts": parts_output, "manifest": manifest_json, "algorithm": algorithm})
    except FileNotFoundError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/contracts/<contract_id>/accept', methods=['POST'])
@login_required
def accept_contract(contract_id):
    """Recipient accepts/receives the contract."""
    success, message = um.accept_contract(contract_id, session['username'])
    if success:
        return jsonify({"success": True, "message": message})
    return jsonify({"success": False, "error": message}), 400


@app.route('/api/contracts/<contract_id>/verify', methods=['POST'])
@login_required
def verify_contract(contract_id):
    contract = um.get_contract(contract_id)
    if not contract:
        return jsonify({"success": False, "error": "Contract not found"}), 404
    if not contract.get('manifest') or not contract.get('parts'):
        return jsonify({"success": False, "error": "Contract not signed yet"}), 400
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
            return jsonify({"success": False, "error": f"No {algorithm} public key found"}), 400
        is_valid, message, reassembled = handler.verify_contract(
            manifest_json=manifest_json, parts=parts, public_key_path=str(pub_key_path)
        )
        return jsonify({"success": True, "is_valid": is_valid, "message": message, "reassembled_contract": reassembled})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/contracts/<contract_id>/delete', methods=['DELETE'])
@login_required
def delete_contract(contract_id):
    contract = um.get_contract(contract_id)
    if not contract:
        return jsonify({"success": False, "error": "Contract not found"}), 404
    if contract['sender'] != session['username']:
        return jsonify({"success": False, "error": "Cannot delete others' contracts"}), 403
    um.delete_contract(contract_id)
    return jsonify({"success": True})


@app.route('/api/contracts/<contract_id>/tamper', methods=['POST'])
@login_required
def tamper_contract(contract_id):
    contract = um.get_contract(contract_id)
    if not contract or not contract.get('parts'):
        return jsonify({"success": False, "error": "Contract not found or not signed"}), 404
    data = request.get_json()
    tamper_type = data.get('tamper_type', 'modify')
    part_index = data.get('part_index', 0)
    parts = list(contract['parts'])
    tamper_desc = ""
    if tamper_type == 'modify':
        parts[part_index]["content"] = "MODIFIED BY ATTACKER!"
        tamper_desc = f"Modified {parts[part_index]['part_id']}"
    elif tamper_type == 'remove':
        removed = parts.pop(part_index)
        tamper_desc = f"Removed {removed['part_id']}"
    elif tamper_type == 'reorder':
        if len(parts) >= 2:
            parts[0], parts[-1] = parts[-1], parts[0]
            tamper_desc = "Reversed order"
    elif tamper_type == 'hash':
        parts[part_index]["hash"] = "0" * 64
        tamper_desc = f"Corrupted hash of {parts[part_index]['part_id']}"
    elif tamper_type == 'signature':
        parts[part_index]["signature"] = "0" * 128
        tamper_desc = f"Corrupted signature of {parts[part_index]['part_id']}"
    return jsonify({"success": True, "parts": parts, "manifest": contract['manifest'], "tamper_desc": tamper_desc, "tamper_type": tamper_type, "algorithm": contract.get('algorithm', 'ed25519')})


@app.route('/api/test/run', methods=['POST'])
@login_required
def run_tests():
    import pytest
    try:
        test_dir = Path(__file__).resolve().parents[2] / "tests"
        result = pytest.main([str(test_dir), "-v", "--tb=line", "--no-header", "-q"])
        return jsonify({"success": True, "passed": result == 0, "exit_code": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/sample/contract', methods=['GET'])
def get_sample_contract():
    sample = """HOP DONG HOP TAC KINH DOANH SO 2024/HD-HT

PHAN 1: THONG TIN CAC BEN
Ben A: CONG TY TNHH GIAI PHAP SO ABC
Ben B: CONG TY CO PHAN CONG NGHE XYZ

PHAN 2: MUC DICH VA PHAM VI HOP TAC
Hai ben cung hop tac phat trien du an "Chuyen doi so toan dien".

PHAN 3: GIA TRI HOP DONG
Tong gia tri hop dong: 15.000.000.000 VND

PHAN 4: HIEU LUC
Hop dong co hieu luc tu ngay 01/01/2025 den 31/12/2027.

PHAN 5: DIEU KHOAN CHUNG
Cac ben cam ket bao mat thong tin."""
    return jsonify({"success": True, "contract": sample})


if __name__ == '__main__':
    print("=" * 60)
    print("  Multi-Part Digital Contract Signing - Web UI")
    print("  Server: http://localhost:5000")
    print("  Supported: Ed25519 / RSA-PSS / ECDSA P-256")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)