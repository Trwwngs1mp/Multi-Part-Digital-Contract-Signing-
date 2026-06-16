#!/usr/bin/env python3
"""
CLI - Command Line Interface for Multi-Part Digital Contract Signing.

Usage:
    python cli.py generate-keys [--algorithm ed25519]
    python cli.py sign <contract_file> [--parts 3] [--output output]
    python cli.py verify <manifest> <parts_dir> [--public-key key.pem]
    python cli.py run-tests
    python cli.py benchmark
"""

import sys
import os
import argparse
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.client.contract_signer import ContractSigner


def main():
    parser = argparse.ArgumentParser(
        description="Multi-Part Digital Contract Signing - CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate Ed25519 keys
  python cli.py generate-keys

  # Generate RSA-PSS keys
  python cli.py generate-keys --algorithm rsa-pss

  # Sign a contract
  python cli.py sign ../sample_data/contract_sample.txt

  # Verify a signed contract
  python cli.py verify output/contract_sample/manifest.json output/contract_sample/parts/

  # Run all tests
  python cli.py run-tests
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # generate-keys command
    gen_parser = subparsers.add_parser("generate-keys", help="Generate a new key pair")
    gen_parser.add_argument(
        "--algorithm", "-a",
        choices=["ed25519", "rsa-pss"],
        default="ed25519",
        help="Signing algorithm (default: ed25519)"
    )

    # sign command
    sign_parser = subparsers.add_parser("sign", help="Sign a contract")
    sign_parser.add_argument(
        "contract_file",
        help="Path to the contract text file"
    )
    sign_parser.add_argument(
        "--parts", "-p",
        type=int,
        default=3,
        help="Number of parts to split into (default: 3)"
    )
    sign_parser.add_argument(
        "--output", "-o",
        default="output",
        help="Output directory (default: output)"
    )
    sign_parser.add_argument(
        "--algorithm", "-a",
        choices=["ed25519", "rsa-pss"],
        default="ed25519",
        help="Signing algorithm (default: ed25519)"
    )

    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a signed contract")
    verify_parser.add_argument(
        "manifest",
        help="Path to the manifest JSON file"
    )
    verify_parser.add_argument(
        "parts_dir",
        help="Directory containing the contract part JSON files"
    )
    verify_parser.add_argument(
        "--public-key", "-k",
        help="Path to the public key PEM file (uses default if not specified)"
    )

    # run-tests command
    test_parser = subparsers.add_parser("run-tests", help="Run all security tests")

    # benchmark command
    bench_parser = subparsers.add_parser("benchmark", help="Run performance benchmark")

    args = parser.parse_args()

    if args.command == "generate-keys":
        signer = ContractSigner(algorithm=args.algorithm)
        signer.generate_keys()
        return 0

    elif args.command == "sign":
        if not Path(args.contract_file).exists():
            print(f"[ERROR] Contract file not found: {args.contract_file}")
            return 1

        signer = ContractSigner(algorithm=args.algorithm)
        signer.sign_contract(
            contract_path=args.contract_file,
            num_parts=args.parts,
            output_dir=args.output
        )
        return 0

    elif args.command == "verify":
        if not Path(args.manifest).exists():
            print(f"[ERROR] Manifest file not found: {args.manifest}")
            return 1
        if not Path(args.parts_dir).exists():
            print(f"[ERROR] Parts directory not found: {args.parts_dir}")
            return 1

        signer = ContractSigner()
        result = signer.verify_contract(
            manifest_path=args.manifest,
            parts_dir=args.parts_dir,
            public_key_path=args.public_key
        )
        return 0 if result else 1

    elif args.command == "run-tests":
        _run_tests()
        return 0

    elif args.command == "benchmark":
        _run_benchmark()
        return 0

    else:
        parser.print_help()
        return 1


def _run_tests():
    """Run the test suite."""
    print("\n" + "=" * 60)
    print("  Running Security Test Suite")
    print("=" * 60 + "\n")

    import pytest
    test_dir = Path(__file__).resolve().parents[2] / "tests"
    exit_code = pytest.main([
        str(test_dir),
        "-v",
        "--tb=short",
        "--no-header"
    ])

    print("\n" + "=" * 60)
    if exit_code == 0:
        print("  ✓ All tests PASSED")
    else:
        print(f"  ✗ Some tests FAILED (exit code: {exit_code})")
    print("=" * 60)


def _run_benchmark():
    """Run performance benchmark."""
    print("\n" + "=" * 60)
    print("  Performance Benchmark")
    print("=" * 60 + "\n")

    import time
    import hashlib

    from src.crypto.crypto_manager import CryptoManager, KeyManager

    # Test data sizes
    sizes = [
        ("1 KB", 1024),
        ("10 KB", 10240),
        ("100 KB", 102400),
        ("1 MB", 1024 * 1024),
    ]

    algorithms = ["ed25519", "rsa-pss"]

    for algo in algorithms:
        print(f"\n--- Algorithm: {algo.upper()} ---")
        print(f"{'Size':<10} {'Sign':<15} {'Verify':<15} {'Hash':<15}")
        print("-" * 55)

        cm = CryptoManager(algorithm=algo)

        # Generate key pair for this algorithm
        if algo == "ed25519":
            priv_pem, pub_pem = KeyManager.generate_ed25519_key_pair()
        else:
            priv_pem, pub_pem = KeyManager.generate_rsa_pss_key_pair()

        priv_key = KeyManager.load_key_from_bytes(priv_pem)
        pub_key = KeyManager.load_key_from_bytes(pub_pem)

        for label, size in sizes:
            data = "x" * size

            # Hash benchmark
            t_start = time.perf_counter()
            for _ in range(100):
                hashlib.sha256(data.encode()).hexdigest()
            hash_time = (time.perf_counter() - t_start) / 100

            # Sign benchmark
            part = cm.sign_part(
                part_id="BENCH", contract_id="BENCH",
                sequence_number=1, content=data,
                private_key=priv_key
            )

            t_start = time.perf_counter()
            for _ in range(10):
                cm.sign_part(
                    part_id="BENCH", contract_id="BENCH",
                    sequence_number=1, content=data,
                    private_key=priv_key
                )
            sign_time = (time.perf_counter() - t_start) / 10

            # Verify benchmark
            t_start = time.perf_counter()
            for _ in range(10):
                cm.verify_part(part, pub_key)
            verify_time = (time.perf_counter() - t_start) / 10

            print(f"{label:<10} {sign_time*1000:<15.4f} {verify_time*1000:<15.4f} {hash_time*1000:<15.4f}")

    print("\n" + "-" * 55)
    print("All times in milliseconds (ms)")
    print("Benchmark completed.")


if __name__ == "__main__":
    sys.exit(main())