"""Tests for MCP Cookie Vault encrypted storage."""

import pytest
import asyncio
from pathlib import Path
import tempfile
import os

from mcp_cookie_vault.models import Cookie, SessionProfile
from mcp_cookie_vault.storage import EncryptedStorage, AuditLog


class MockKeyring:
    """Mock keyring for testing without OS keyring."""

    def __init__(self):
        self._passwords = {}

    def get_password(self, service, name):
        return self._passwords.get(f"{service}:{name}")

    def set_password(self, service, name, password):
        self._passwords[f"{service}:{name}"] = password


@pytest.fixture
def mock_keyring(monkeypatch):
    """Fixture to mock keyring."""
    mock = MockKeyring()

    def mock_get_keyring():
        return mock

    monkeypatch.setattr("mcp_cookie_vault.storage.EncryptedStorage._get_keyring", mock_get_keyring)
    return mock


@pytest.fixture
def temp_vault(mock_keyring):
    """Fixture to create temporary vault."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = EncryptedStorage(tmpdir)
        yield storage


class TestEncryptedStorage:
    """Tests for EncryptedStorage."""

    def test_save_and_load_profile(self, temp_vault):
        """Test saving and loading a profile."""
        profile = SessionProfile(
            label="test-profile",
            domain="example.com",
            cookies=[Cookie("session", "secret123", "example.com")],
            local_storage={"key": "value"},
            tags=["test"],
        )

        # Save
        asyncio.run(temp_vault.save_profile(profile))

        # Load
        loaded = asyncio.run(temp_vault.load_profile("test-profile"))

        assert loaded is not None
        assert loaded.label == "test-profile"
        assert loaded.domain == "example.com"
        assert len(loaded.cookies) == 1
        assert loaded.cookies[0].value == "secret123"
        assert loaded.local_storage == {"key": "value"}

    def test_load_nonexistent_profile(self, temp_vault):
        """Test loading a profile that doesn't exist."""
        loaded = asyncio.run(temp_vault.load_profile("nonexistent"))
        assert loaded is None

    def test_delete_profile(self, temp_vault):
        """Test deleting a profile."""
        profile = SessionProfile("test", "example.com")
        asyncio.run(temp_vault.save_profile(profile))

        # Delete
        deleted = asyncio.run(temp_vault.delete_profile("test"))
        assert deleted is True

        # Verify deleted
        loaded = asyncio.run(temp_vault.load_profile("test"))
        assert loaded is None

        # Delete again (should return False)
        deleted = asyncio.run(temp_vault.delete_profile("test"))
        assert deleted is False

    def test_list_profiles(self, temp_vault):
        """Test listing profiles."""
        # Create multiple profiles
        profiles = [
            SessionProfile("profile1", "example.com", tags=["test"]),
            SessionProfile("profile2", "google.com", tags=["work"]),
            SessionProfile("profile3", "example.com", tags=["test"]),
        ]

        for p in profiles:
            asyncio.run(temp_vault.save_profile(p))

        # List
        listed = asyncio.run(temp_vault.list_profiles())

        assert len(listed) == 3
        labels = [p.label for p in listed]
        assert "profile1" in labels
        assert "profile2" in labels
        assert "profile3" in labels

    def test_profile_exists(self, temp_vault):
        """Test checking profile existence."""
        assert asyncio.run(temp_vault.profile_exists("test")) is False

        profile = SessionProfile("test", "example.com")
        asyncio.run(temp_vault.save_profile(profile))

        assert asyncio.run(temp_vault.profile_exists("test")) is True

    def test_get_metadata(self, temp_vault):
        """Test getting metadata without full decryption."""
        profile = SessionProfile(
            label="test",
            domain="example.com",
            cookies=[Cookie("session", "secret", "example.com")],
        )
        asyncio.run(temp_vault.save_profile(profile))

        metadata = asyncio.run(temp_vault.get_metadata("test"))

        assert metadata is not None
        assert metadata["label"] == "test"
        assert metadata["domain"] == "example.com"
        assert metadata["cookie_count"] == 1

        # Values should not be in metadata
        assert "value" not in str(metadata)

    def test_update_access(self, temp_vault):
        """Test updating access statistics."""
        profile = SessionProfile("test", "example.com")
        asyncio.run(temp_vault.save_profile(profile))

        # Update access
        updated = asyncio.run(temp_vault.update_access("test"))
        assert updated is True

        # Check stats updated
        loaded = asyncio.run(temp_vault.load_profile("test"))
        assert loaded.access_count == 1
        assert loaded.last_used is not None

    def test_encryption(self, temp_vault):
        """Test that data is actually encrypted on disk."""
        profile = SessionProfile(
            label="test",
            domain="example.com",
            cookies=[Cookie("session", "super_secret_value", "example.com")],
        )
        asyncio.run(temp_vault.save_profile(profile))

        # Read raw file
        profile_path = temp_vault._get_profile_path("test")
        raw_data = profile_path.read_bytes()

        # Should not contain plaintext secrets
        assert b"super_secret_value" not in raw_data
        assert b"session" not in raw_data  # Even cookie name should be encrypted

    def test_corrupted_file_handling(self, temp_vault):
        """Test handling of corrupted profile files."""
        # Create a corrupted file
        profile_path = temp_vault._get_profile_path("corrupted")
        profile_path.write_bytes(b"not valid encrypted data")

        # Should not crash, just skip corrupted file
        profiles = asyncio.run(temp_vault.list_profiles())
        assert len(profiles) == 0


class TestAuditLog:
    """Tests for AuditLog."""

    @pytest.fixture
    def temp_log(self):
        """Fixture for temporary audit log."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log = AuditLog(tmpdir)
            yield log

    def test_log_entry(self, temp_log):
        """Test logging an entry."""
        asyncio.run(temp_log.log(
            action="save",
            profile_label="test-profile",
            details="15 cookies",
            success=True,
        ))

        # Read log file
        assert temp_log.log_path.exists()
        content = temp_log.log_path.read_text()

        assert "SAVE" in content
        assert "test-profile" in content
        assert "OK" in content

    def test_get_entries(self, temp_log):
        """Test retrieving log entries."""
        # Add entries
        asyncio.run(temp_log.log("save", "profile1", success=True))
        asyncio.run(temp_log.log("load", "profile1", target="playwright", success=True))
        asyncio.run(temp_log.log("delete", "profile2", success=False, error="not found"))

        # Get entries
        entries = asyncio.run(temp_log.get_entries())

        assert len(entries) == 3
        assert entries[0].action == "save"
        assert entries[1].action == "load"
        assert entries[2].action == "delete"

    def test_search_entries(self, temp_log):
        """Test searching log entries."""
        asyncio.run(temp_log.log("save", "profile1", success=True))
        asyncio.run(temp_log.log("load", "profile1", target="playwright", success=True))
        asyncio.run(temp_log.log("load", "profile2", target="requests", success=True))
        asyncio.run(temp_log.log("delete", "profile1", success=True))

        # Search by profile
        profile1_entries = asyncio.run(temp_log.search(profile_label="profile1"))
        assert len(profile1_entries) == 3

        # Search by action
        load_entries = asyncio.run(temp_log.search(action="load"))
        assert len(load_entries) == 2

    def test_clear_log(self, temp_log):
        """Test clearing the audit log."""
        asyncio.run(temp_log.log("save", "test", success=True))
        asyncio.run(temp_log.log("load", "test", success=True))

        count = asyncio.run(temp_log.clear())
        assert count == 2

        # Verify cleared
        entries = asyncio.run(temp_log.get_entries())
        assert len(entries) == 0

    def test_log_line_format(self, temp_log):
        """Test log line format."""
        asyncio.run(temp_log.log(
            action="export",
            profile_label="test",
            target="json",
            details="/path/to/file.json",
            success=True,
        ))

        content = temp_log.log_path.read_text().strip()
        
        # Should match format: [timestamp] ACTION->target profile [details] - STATUS
        assert "[" in content
        assert "]" in content
        assert "EXPORT->json" in content
        assert "test" in content
        assert "OK" in content
