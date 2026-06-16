#!/usr/bin/env python3
"""
Web Application - Multi-Part Digital Contract Signing
Modern dark-themed UI for signing and verifying contracts.
"""

import sys, os, json, tempfile, shutil
from pathlib import Path
from flask import Flask, render_template, request, jsonify

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.crypto.crypto_manager import CryptoManager, KeyManager
from src.server.contract_handler import ContractHandler
from src.server.manifest import ManifestManager
from src.utils.logger import SecurityLogger
from src.utils.replay_protection import ReplayProtection

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32).hex()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

TEMP_DIR = Path(tempfile.gettempdir()) / "contract_signing_web"
TEMP_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_CONTRACT = """HỢP ĐỒNG HỢP TÁC KINH DOANH SỐ 2024/HD-HT

PHẦN 1: THÔNG TIN CÁC BÊN

Bên A: CÔNG TY TNHH GIẢI PHÁP SỐ ABC
Địa chỉ: 123 Nguyễn Huệ, Quận 1, TP. Hồ Chí Minh
Mã số thuế: 0123456789
Đại diện: Ông Nguyễn Văn An - Giám đốc

Bên B: CÔNG TY CỔ PHẦN CÔNG NGHỆ XYZ
Địa chỉ: 456 Lê Lợi, Quận 3, TP. Hồ Chí Minh
Mã số thuế: 0987654321
Đại diện: Bà Trần Thị Bình - Tổng Giám đốc

PHẦN 2: MỤC ĐÍCH VÀ PHẠM VI HỢP TÁC

Điều 2.1: Mục đích hợp tác
Hai bên cùng hợp tác phát triển dự án "Chuyển đổi số toàn diện".

Điều 2.2: Phạm vi hợp tác
- Phát triển nền tảng quản lý doanh nghiệp tích hợp AI
- Cung cấp dịch vụ tư vấn chuyển đổi số
- Đào tạo nhân sự vận hành hệ thống

Điều 2.3: Thời hạn hợp tác
Hợp đồng có hiệu lực từ ngày 01/01/2025 đến ngày 31/12/2027 (03 năm).

PHẦN 3: QUYỀN VÀ NGHĨA VỤ CỦA CÁC BÊN

Điều 3.1: Quyền và nghĩa vụ của Bên A
- Cung cấp giải pháp công nghệ nền tảng
- Đảm bảo bản quyền phần mềm và sở hữu trí tuệ
- Hỗ trợ kỹ thuật 24/7 trong suốt thời gian hợp đồng

Điều 3.2: Quyền và nghĩa vụ của Bên B
- Cung cấp cơ sở vật chất và hạ tầng triển khai
- Đảm bảo nguồn nhân lực tham gia dự án
- Thanh toán đầy đủ và đúng hạn theo thỏa thuận

PHẦN 4: GIÁ TRỊ HỢP ĐỒNG VÀ PHƯƠNG THỨC THANH TOÁN

Điều 4.1: Tổng giá trị hợp đồng: 15.000.000.000 VNĐ

Điều 4.2: Phương thức thanh toán
- Đợt 1 (30%): Sau khi ký hợp đồng - 4.500.000.000 VNĐ
- Đợt 2 (40%): Sau khi bàn giao giai đoạn 1 - 6.000.000.000 VNĐ
- Đợt 3 (30%): Sau khi nghiệm thu toàn bộ - 4.500.000.000 VNĐ

PHẦN 5: ĐIỀU KHOẢN CHUNG

Điều 5.1: Bảo mật thông tin
Các bên cam kết bảo mật mọi thông tin liên quan đến hợp đồng.

Điều 5.2: Giải quyết tranh chấp
Mọi tranh chấp sẽ được giải quyết tại Tòa án Nhân dân TP. Hồ Chí Minh.

Điều 5.3: Điều khoản cuối cùng
Hợp đồng được lập thành 04 bản có giá trị pháp lý như nhau."""


def get_crypto_context(algorithm="ed25519"):
    """Get or create a crypto context with keys."""
    logger = SecurityLogger(log_dir=str(TEMP_DIR / "logs"))
    crypto = CryptoManager(algorithm=algorithm)
    handler = ContractHandler(crypto_manager=crypto, logger=logger)
    return crypto, handler, logger


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/keys/status', methods=['GET'])
def key_status():
    """Check if keys exist."""
    key_dir = KeyManager.DEFAULT_KEY_DIR
    ed25519_exists = (key_dir / "ed25519_private.pem").exists()
    rsa_exists = (key_dir / "rsa-pss_private.pem").exists()

    has_keys = ed25519_exists or rsa_exists

    # Load keys info
    keys_info = []
    if ed25519_exists:
        pub = (key_dir / "ed25519_public.pem").read_text()
        keys_info.append({
            "algorithm": "Ed25519",
            "status": "active",
            "public_key": pub[-80:].strip()
        })
    if rsa_exists:
        pub = (key_dir / "rsa-pss_public.pem").read_text()
        keys_info.append({
            "algorithm": "RSA-PSS (2048)",
            "status": "active",
            "public_key": pub[-80:].strip()
        })

    return jsonify({
        "has_keys": has_keys,
        "keys": keys_info,
        "key_dir": str(key_dir)
    })


@app.route('/api/keys/generate', methods=['POST'])
def generate_keys():
    """Generate a new key pair."""
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

        return jsonify({
            "success": True,
            "algorithm": algorithm,
            "message": f"{'Ed25519' if algorithm == 'ed25519' else 'RSA-PSS'} keys generated successfully",
            "private_key_path": str(key_dir / f"{algorithm}_private.pem"),
            "public_key_path": str(key_dir / f"{algorithm}_public.pem")
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/contract/sign', methods=['POST'])
def sign_contract():
    """Sign a contract: split into parts, sign each, create manifest."""
    data = request.get_json()
    contract_text = data.get('contract', SAMPLE_CONTRACT)
    algorithm = data.get('algorithm', 'ed25519')
    num_parts = data.get('num_parts', 3)

    try:
        # Check keys exist
        key_dir = KeyManager.DEFAULT_KEY_DIR
        key_path = key_dir / f"{algorithm}_private.pem"
        if not key_path.exists():
            return jsonify({"success": False, "error": "No keys found. Generate keys first."}), 400

        crypto, handler, logger = get_crypto_context(algorithm)

        manifest_json, parts = handler.split_contract(
            contract_text=contract_text,
            contract_id=f"CONTRACT-{os.urandom(4).hex().upper()}",
            num_parts=num_parts
        )

        manifest = json.loads(manifest_json)

        # Format parts for output
        parts_output = []
        for p in parts:
            parts_output.append({
                "part_id": p["part_id"],
                "sequence_number": p["sequence_number"],
                "hash": p["hash"][:16] + "...",
                "signature": p["signature"][:24] + "...",
                "content_preview": p["content"][:100] + ("..." if len(p["content"]) > 100 else ""),
                "algorithm": p["algorithm"]
            })

        return jsonify({
            "success": True,
            "contract_id": manifest["contract_id"],
            "total_parts": len(parts),
            "parts": parts_output,
            "manifest": manifest_json,
            "algorithm": algorithm
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/contract/verify', methods=['POST'])
def verify_contract():
    """Verify a signed contract."""
    data = request.get_json()
    manifest_json = data.get('manifest')
    parts_data = data.get('parts')
    algorithm = data.get('algorithm', 'ed25519')

    if not manifest_json or not parts_data:
        return jsonify({"success": False, "error": "Missing manifest or parts data"}), 400

    try:
        crypto = CryptoManager(algorithm=algorithm)
        logger = SecurityLogger(log_dir=str(TEMP_DIR / "logs"))
        handler = ContractHandler(crypto_manager=crypto, logger=logger)

        # Reconstruct parts from the received data
        parts = []
        for p in parts_data:
            parts.append({
                "part_id": p["part_id"],
                "contract_id": p["contract_id"],
                "sequence_number": p["sequence_number"],
                "content": p["content"],
                "hash": p["hash"],
                "signature": p["signature"],
                "algorithm": p["algorithm"]
            })

        key_dir = KeyManager.DEFAULT_KEY_DIR
        pub_key_path = key_dir / f"{algorithm}_public.pem"

        if not pub_key_path.exists():
            return jsonify({"success": False, "error": "No public key found. Generate keys first."}), 400

        is_valid, message, reassembled = handler.verify_contract(
            manifest_json=manifest_json,
            parts=parts,
            public_key_path=str(pub_key_path)
        )

        return jsonify({
            "success": True,
            "is_valid": is_valid,
            "message": message,
            "reassembled_contract": reassembled
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/contract/tamper', methods=['POST'])
def tamper_test():
    """Simulate a tampering attack on a part."""
    data = request.get_json()
    parts_data = data.get('parts', [])
    tamper_type = data.get('tamper_type', 'modify')
    part_index = data.get('part_index', 0)

    if not parts_data:
        return jsonify({"success": False, "error": "No parts data"}), 400

    try:
        parts = list(parts_data)
        tamper_desc = ""

        if tamper_type == 'modify':
            parts[part_index]["content"] = "⚠️ NỘI DUNG ĐÃ BỊ THAY ĐỔI BỞI KẺ TẤN CÔNG! ⚠️"
            tamper_desc = f"Modified content of {parts[part_index]['part_id']}"
        elif tamper_type == 'remove':
            removed = parts.pop(part_index)
            tamper_desc = f"Removed {removed['part_id']} from the contract"
        elif tamper_type == 'reorder':
            if len(parts) >= 2:
                parts[0], parts[-1] = parts[-1], parts[0]
                tamper_desc = f"Swapped positions of {parts[0]['part_id']} and {parts[-1]['part_id']}"
        elif tamper_type == 'hash':
            parts[part_index]["hash"] = "0" * 64
            tamper_desc = f"Corrupted hash of {parts[part_index]['part_id']}"
        elif tamper_type == 'signature':
            parts[part_index]["signature"] = "0" * 128
            tamper_desc = f"Corrupted signature of {parts[part_index]['part_id']}"

        return jsonify({
            "success": True,
            "parts": parts,
            "tamper_desc": tamper_desc,
            "tamper_type": tamper_type
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/test/run', methods=['POST'])
def run_tests():
    """Run the security test suite and return results."""
    import subprocess
    import pytest

    try:
        test_dir = Path(__file__).resolve().parents[2] / "tests"

        # Capture pytest output
        result = pytest.main([
            str(test_dir),
            "-v",
            "--tb=line",
            "--no-header",
            "-q"
        ])

        passed = result == 0

        return jsonify({
            "success": True,
            "passed": passed,
            "exit_code": result
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/sample/contract', methods=['GET'])
def get_sample_contract():
    """Return the sample contract text."""
    return jsonify({
        "success": True,
        "contract": SAMPLE_CONTRACT
    })


if __name__ == '__main__':
    print("=" * 60)
    print("  Multi-Part Digital Contract Signing - Web UI")
    print("  Starting server at http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)