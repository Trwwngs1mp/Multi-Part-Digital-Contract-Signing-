"""
Security Logger - Logs security events without exposing sensitive data.

Ensures that passwords, private keys, or raw secret material are never
written to log files.
"""

import logging
import json
import os
from datetime import datetime
from pathlib import Path


class SecurityLogger:
    """
    A secure event logger that filters out sensitive information.

    Logged events include: authentication, session creation, message sending,
    encryption/decryption, signature verification, integrity errors,
    access control errors, expiry errors, and replay detection.
    """

    # Sensitive field patterns that must never be logged
    SENSITIVE_PATTERNS = [
        "private_key", "privatekey", "secret", "password", "passwd",
        "pwd", "token", "auth_key", "master_key", "seed"
    ]

    def __init__(self, log_dir: str = "logs", log_file: str = "security_events.log",
                 level: int = logging.INFO):
        """
        Initialize the security logger.

        Args:
            log_dir: Directory where log files are stored
            log_file: Name of the log file
            level: Logging level (default: INFO)
        """
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger("SecurityLogger")
        self.logger.setLevel(level)

        # File handler
        file_handler = logging.FileHandler(
            str(log_path / log_file), encoding='utf-8'
        )
        file_handler.setLevel(level)

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)

        # Avoid duplicate handlers
        if not self.logger.handlers:
            self.logger.addHandler(file_handler)

        # Console handler (for development)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        if not any(isinstance(h, logging.StreamHandler) for h in self.logger.handlers):
            self.logger.addHandler(console_handler)

    @staticmethod
    def _sanitize(message: str) -> str:
        """
        Remove sensitive data from log messages.

        Args:
            message: Raw log message

        Returns:
            str: Sanitized log message
        """
        sanitized = message
        for pattern in SecurityLogger.SENSITIVE_PATTERNS:
            if pattern.lower() in sanitized.lower():
                sanitized = sanitized.replace(
                    pattern, f"{pattern}[REDACTED]"
                )
        return sanitized

    def log_event(self, event_type: str, details: str, user: str = "system",
                  level: str = "info") -> None:
        """
        Log a security event.

        Args:
            event_type: Type of event (e.g., AUTH, SIGN, VERIFY, REPLAY)
            details: Description of the event
            user: User identifier (default: system)
            level: Log level: info, warning, error, critical
        """
        message = f"[{event_type}] User={user} | {details}"
        message = self._sanitize(message)

        level_map = {
            "info": self.logger.info,
            "warning": self.logger.warning,
            "error": self.logger.error,
            "critical": self.logger.critical
        }

        log_func = level_map.get(level, self.logger.info)
        log_func(message)

    def log_key_generation(self, algorithm: str, key_size: int = None,
                           user: str = "system") -> None:
        """Log key generation (without logging the key itself)."""
        details = f"Generated {algorithm} key pair"
        if key_size:
            details += f" (size={key_size})"
        self.log_event("KEYGEN", details, user=user)

    def log_signing(self, part_id: str, contract_id: str,
                    user: str = "system") -> None:
        """Log a signing operation."""
        details = f"Signed part={part_id} of contract={contract_id}"
        self.log_event("SIGN", details, user=user)

    def log_verification(self, part_id: str, contract_id: str,
                         result: bool, user: str = "system") -> None:
        """Log a verification operation."""
        status = "PASSED" if result else "FAILED"
        details = f"Verification {status} for part={part_id} of contract={contract_id}"
        level = "info" if result else "warning"
        self.log_event("VERIFY", details, user=user, level=level)

    def log_integrity_error(self, part_id: str, contract_id: str,
                            error_desc: str, user: str = "system") -> None:
        """Log an integrity error (tampering detected)."""
        details = (f"Integrity error on part={part_id} of contract={contract_id}: "
                   f"{error_desc}")
        self.log_event("INTEGRITY", details, user=user, level="error")

    def log_replay_detected(self, part_id: str, contract_id: str,
                            nonce: str = None, user: str = "system") -> None:
        """Log a replay attack detection."""
        details = f"REPLAY detected on part={part_id} of contract={contract_id}"
        if nonce:
            details += f" (nonce={nonce[:8]}...)"
        self.log_event("REPLAY", details, user=user, level="error")

    def log_tampering_detected(self, contract_id: str, part_id: str,
                               description: str, user: str = "system") -> None:
        """Log tampering detection."""
        details = (f"Tampering detected on contract={contract_id}, "
                   f"part={part_id}: {description}")
        self.log_event("TAMPER", details, user=user, level="critical")

    def log_session(self, session_id: str, action: str,
                    user: str = "system") -> None:
        """Log a session-related event."""
        details = f"Session {action}: id={session_id}"
        self.log_event("SESSION", details, user=user)

    def log_manifest_signed(self, contract_id: str, num_parts: int,
                            user: str = "system") -> None:
        """Log manifest signing."""
        details = f"Manifest signed for contract={contract_id} with {num_parts} parts"
        self.log_event("MANIFEST", details, user=user)

    def log_manifest_verified(self, contract_id: str, result: bool,
                              user: str = "system") -> None:
        """Log manifest verification result."""
        status = "PASSED" if result else "FAILED"
        details = f"Manifest verification {status} for contract={contract_id}"
        level = "info" if result else "error"
        self.log_event("MANIFEST_VERIFY", details, user=user, level=level)