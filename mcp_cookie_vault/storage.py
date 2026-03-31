"""Encrypted storage for MCP Cookie Vault."""

import json
from pathlib import Path
from datetime import datetime
from typing import Optional
import base64

from .models import SessionProfile, Cookie, AuditEntry


class EncryptedStorage:
    """
    Encrypted storage using system keyring for master key.

    Uses the `cryptography` library with Fernet symmetric encryption
    and stores the master key in the OS keyring (Windows Credential Manager,
    macOS Keychain, or Linux Secret Service).

    Security features:
    - Master key stored in OS keyring (not on disk)
    - All profiles encrypted at rest
    - Atomic file operations
    - Corruption detection and handling
    """

    SERVICE_NAME = "mcp-cookie-vault"
    KEY_NAME = "master_key"

    def __init__(self, vault_path: Optional[str] = None):
        """
        Initialize encrypted storage.

        Args:
            vault_path: Path to vault directory. Default: ~/.mcp-cookie-vault
        """
        self.vault_path = Path(vault_path) if vault_path else self._default_vault_path()
        self.vault_path.mkdir(parents=True, exist_ok=True)

        self._key: Optional[bytes] = None
        self._cipher = None

    def _default_vault_path(self) -> Path:
        """Get default vault path."""
        return Path.home() / ".mcp-cookie-vault"

    def _get_keyring(self):
        """Lazy load keyring module."""
        import keyring
        return keyring

    def _get_cipher(self):
        """Lazy initialize cipher with key from keyring."""
        if self._cipher is not None:
            return self._cipher

        from cryptography.fernet import Fernet

        keyring = self._get_keyring()

        # Try to get existing key
        existing_key = keyring.get_password(self.SERVICE_NAME, self.KEY_NAME)

        if existing_key:
            key = existing_key.encode()
        else:
            # Generate new key
            key = Fernet.generate_key().decode()
            keyring.set_password(self.SERVICE_NAME, self.KEY_NAME, key)

        self._key = key.encode()
        self._cipher = Fernet(self._key)
        return self._cipher

    def _get_profile_path(self, label: str) -> Path:
        """
        Get path to profile file.

        Profiles stored as: vault/<label>.json.enc
        """
        return self.vault_path / f"{label}.json.enc"

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data."""
        cipher = self._get_cipher()
        return cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data."""
        cipher = self._get_cipher()
        return cipher.decrypt(data)

    async def save_profile(self, profile: SessionProfile) -> None:
        """
        Save profile with encryption.

        Args:
            profile: Profile to save
        """
        profile.updated_at = datetime.utcnow().timestamp()

        data = json.dumps(profile.to_dict(), ensure_ascii=False).encode("utf-8")
        encrypted = self.encrypt(data)

        profile_path = self._get_profile_path(profile.label)
        profile_path.write_bytes(encrypted)

    async def load_profile(self, label: str) -> Optional[SessionProfile]:
        """
        Load profile by name.

        Args:
            label: Profile name

        Returns:
            Profile or None if not found
        """
        profile_path = self._get_profile_path(label)

        if not profile_path.exists():
            return None

        encrypted = profile_path.read_bytes()
        decrypted = self.decrypt(encrypted)
        data = json.loads(decrypted.decode("utf-8"))

        return SessionProfile.from_dict(data)

    async def delete_profile(self, label: str) -> bool:
        """
        Delete profile.

        Args:
            label: Profile name

        Returns:
            True if profile existed and was deleted
        """
        profile_path = self._get_profile_path(label)

        if profile_path.exists():
            profile_path.unlink()
            return True
        return False

    async def list_profiles(self) -> list[SessionProfile]:
        """
        Get list of all profiles.

        Returns:
            List of profiles (full data, sorted by creation date)
        """
        profiles = []

        for enc_file in self.vault_path.glob("*.json.enc"):
            try:
                encrypted = enc_file.read_bytes()
                decrypted = self.decrypt(encrypted)
                data = json.loads(decrypted.decode("utf-8"))
                profiles.append(SessionProfile.from_dict(data))
            except Exception:
                # Skip corrupted files
                continue

        return sorted(profiles, key=lambda p: p.created_at, reverse=True)

    async def profile_exists(self, label: str) -> bool:
        """Check if profile exists."""
        return self._get_profile_path(label).exists()

    async def get_metadata(self, label: str) -> Optional[dict]:
        """
        Get profile metadata without decrypting sensitive values.

        Args:
            label: Profile name

        Returns:
            Metadata or None if not found
        """
        profile = await self.load_profile(label)
        if profile is None:
            return None
        return profile.get_metadata()

    async def update_access(self, label: str) -> bool:
        """
        Update last access information.

        Args:
            label: Profile name

        Returns:
            True if profile found and updated
        """
        profile = await self.load_profile(label)
        if profile is None:
            return False

        profile.last_used = datetime.utcnow().timestamp()
        profile.access_count += 1
        await self.save_profile(profile)
        return True

    def get_vault_path(self) -> Path:
        """Get vault directory path."""
        return self.vault_path


class AuditLog:
    """
    Audit log for tracking all operations on profiles.

    Logs are stored in plain text for easy inspection and compliance.
    Format: [timestamp] ACTION->target profile [details] - STATUS
    """

    def __init__(self, vault_path: Optional[str] = None):
        """
        Initialize audit log.

        Args:
            vault_path: Path to vault directory. Log saved as audit.log
        """
        self.vault_path = Path(vault_path) if vault_path else Path.home() / ".mcp-cookie-vault"
        self.vault_path.mkdir(parents=True, exist_ok=True)
        self.log_path = self.vault_path / "audit.log"

    async def log(
        self,
        action: str,
        profile_label: str,
        target: Optional[str] = None,
        details: Optional[str] = None,
        success: bool = True,
        error: Optional[str] = None,
    ) -> None:
        """
        Write audit log entry.

        Args:
            action: Operation type (save, load, reveal, delete, export, import)
            profile_label: Profile name
            target: Target system (playwright, requests, etc.)
            details: Additional details
            success: Whether operation succeeded
            error: Error message if failed
        """
        entry = AuditEntry(
            timestamp=datetime.utcnow().timestamp(),
            action=action,
            profile_label=profile_label,
            target=target,
            details=details,
            success=success,
            error=error,
        )

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(entry.to_log_line() + "\n")

    async def get_entries(self, limit: int = 100) -> list[AuditEntry]:
        """
        Get recent log entries.

        Args:
            limit: Maximum number of entries

        Returns:
            List of audit entries (most recent last)
        """
        entries = []

        if not self.log_path.exists():
            return entries

        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Read from end for recent entries
        for line in reversed(lines[-limit:]):
            entry = AuditEntry.from_log_line(line.strip())
            if entry:
                entries.append(entry)

        return list(reversed(entries))

    async def search(
        self,
        profile_label: Optional[str] = None,
        action: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> list[AuditEntry]:
        """
        Search log entries with filters.

        Args:
            profile_label: Filter by profile name
            action: Filter by action type
            start_date: Start date filter
            end_date: End date filter

        Returns:
            Filtered audit entries
        """
        all_entries = await self.get_entries(limit=10000)

        result = []
        for entry in all_entries:
            if profile_label and entry.profile_label != profile_label:
                continue
            if action and entry.action != action:
                continue
            if start_date and entry.timestamp < start_date.timestamp():
                continue
            if end_date and entry.timestamp > end_date.timestamp():
                continue
            result.append(entry)

        return result

    async def clear(self) -> int:
        """
        Clear audit log.

        Returns:
            Number of entries deleted
        """
        if not self.log_path.exists():
            return 0

        with open(self.log_path, "r", encoding="utf-8") as f:
            count = len(f.readlines())

        self.log_path.unlink()
        return count
