"""Tests for MCP Cookie Vault data models."""

import pytest
import json
from datetime import datetime, timedelta

from mcp_cookie_vault.models import Cookie, SessionProfile, AuditEntry


class TestCookie:
    """Tests for Cookie model."""

    def test_create_cookie(self):
        """Test basic cookie creation."""
        cookie = Cookie(
            name="session_id",
            value="abc123",
            domain=".example.com",
            path="/",
            http_only=True,
            secure=True,
        )
        assert cookie.name == "session_id"
        assert cookie.value == "abc123"
        assert cookie.domain == ".example.com"

    def test_is_expired(self):
        """Test expiration check."""
        # Not expired
        future = datetime.utcnow().timestamp() + 3600
        cookie = Cookie("test", "val", "example.com", expires=future)
        assert not cookie.is_expired()

        # Expired
        past = datetime.utcnow().timestamp() - 3600
        cookie = Cookie("test", "val", "example.com", expires=past)
        assert cookie.is_expired()

        # Session cookie (no expiry)
        cookie = Cookie("test", "val", "example.com")
        assert not cookie.is_expired()

    def test_to_playwright(self):
        """Test conversion to Playwright format."""
        cookie = Cookie(
            name="test",
            value="value",
            domain=".example.com",
            path="/test",
            expires=1234567890,
            http_only=True,
            secure=True,
            same_site="strict",
        )
        pw = cookie.to_playwright()

        assert pw["name"] == "test"
        assert pw["value"] == "value"
        assert pw["domain"] == ".example.com"
        assert pw["path"] == "/test"
        assert pw["expires"] == 1234567890
        assert pw["httpOnly"] is True
        assert pw["secure"] is True
        assert pw["sameSite"] == "strict"

    def test_to_requests(self):
        """Test conversion to requests format."""
        cookie = Cookie("test", "value", "example.com")
        req = cookie.to_requests()

        assert req == {"name": "test", "value": "value"}

    def test_to_netscape(self):
        """Test conversion to Netscape format."""
        cookie = Cookie(
            name="test",
            value="value",
            domain="example.com",
            path="/",
            expires=1234567890,
            secure=True,
        )
        netscape = cookie.to_netscape()

        assert "example.com" in netscape
        assert "TRUE" in netscape  # secure
        assert "1234567890" in netscape
        assert "test" in netscape
        assert "value" in netscape

    def test_from_playwright(self):
        """Test creation from Playwright format."""
        pw_data = {
            "name": "test",
            "value": "value",
            "domain": ".example.com",
            "path": "/path",
            "expires": 1234567890,
            "httpOnly": True,
            "secure": False,
            "sameSite": "none",
        }
        cookie = Cookie.from_playwright(pw_data)

        assert cookie.name == "test"
        assert cookie.value == "value"
        assert cookie.domain == ".example.com"
        assert cookie.path == "/path"
        assert cookie.expires == 1234567890
        assert cookie.http_only is True
        assert cookie.secure is False
        assert cookie.same_site == "none"

    def test_from_netscape_line(self):
        """Test parsing from Netscape format."""
        line = "example.com\tTRUE\t/\tTRUE\t1234567890\ttest\tvalue"
        cookie = Cookie.from_netscape_line(line)

        assert cookie is not None
        assert cookie.domain == "example.com"
        assert cookie.path == "/"
        assert cookie.secure is True
        assert cookie.expires == 1234567890
        assert cookie.name == "test"
        assert cookie.value == "value"

    def test_from_netscape_comment(self):
        """Test parsing comment lines."""
        assert Cookie.from_netscape_line("# comment") is None
        assert Cookie.from_netscape_line("") is None


class TestSessionProfile:
    """Tests for SessionProfile model."""

    def test_create_profile(self):
        """Test basic profile creation."""
        profile = SessionProfile(
            label="test-profile",
            domain="example.com",
            tags=["test", "dev"],
        )
        assert profile.label == "test-profile"
        assert profile.domain == "example.com"
        assert "test" in profile.tags
        assert "dev" in profile.tags

    def test_to_dict(self):
        """Test serialization to dict."""
        profile = SessionProfile(
            label="test",
            domain="example.com",
            cookies=[Cookie("test", "val", "example.com")],
            local_storage={"key": "value"},
            tags=["test"],
        )
        data = profile.to_dict()

        assert data["label"] == "test"
        assert data["domain"] == "example.com"
        assert len(data["cookies"]) == 1
        assert data["local_storage"] == {"key": "value"}
        assert data["tags"] == ["test"]

    def test_from_dict(self):
        """Test deserialization from dict."""
        data = {
            "label": "test",
            "domain": "example.com",
            "cookies": [
                {
                    "name": "test",
                    "value": "val",
                    "domain": "example.com",
                    "path": "/",
                    "expires": None,
                    "http_only": True,
                    "secure": True,
                    "same_site": "lax",
                }
            ],
            "local_storage": {"key": "value"},
            "tags": ["test"],
            "created_at": datetime.utcnow().timestamp(),
            "updated_at": datetime.utcnow().timestamp(),
        }
        profile = SessionProfile.from_dict(data)

        assert profile.label == "test"
        assert profile.domain == "example.com"
        assert len(profile.cookies) == 1
        assert profile.local_storage == {"key": "value"}

    def test_get_metadata(self):
        """Test metadata extraction (without sensitive values)."""
        profile = SessionProfile(
            label="test",
            domain="example.com",
            cookies=[
                Cookie("session", "secret123", "example.com"),
                Cookie("token", "abc", "example.com"),
            ],
            local_storage={"key1": "val1", "key2": "val2"},
        )
        metadata = profile.get_metadata()

        # Should include
        assert metadata["label"] == "test"
        assert metadata["domain"] == "example.com"
        assert metadata["cookie_count"] == 2
        assert metadata["local_storage_count"] == 2
        assert "cookies_summary" in metadata

        # Should NOT include actual values
        for cookie_summary in metadata["cookies_summary"]:
            assert "value" not in cookie_summary
            assert cookie_summary["name"] in ["session", "token"]

    def test_roundtrip(self):
        """Test serialize/deserialize roundtrip."""
        original = SessionProfile(
            label="roundtrip-test",
            domain="example.com",
            cookies=[Cookie("test", "secret", "example.com")],
            local_storage={"key": "value"},
            tags=["test"],
            notes="Test profile",
        )

        data = original.to_dict()
        restored = SessionProfile.from_dict(data)

        assert restored.label == original.label
        assert restored.domain == original.domain
        assert len(restored.cookies) == len(original.cookies)
        assert restored.local_storage == original.local_storage
        assert restored.tags == original.tags


class TestAuditEntry:
    """Tests for AuditEntry model."""

    def test_create_entry(self):
        """Test basic audit entry creation."""
        entry = AuditEntry(
            timestamp=datetime.utcnow().timestamp(),
            action="save",
            profile_label="test-profile",
            success=True,
        )
        assert entry.action == "save"
        assert entry.profile_label == "test-profile"
        assert entry.success is True

    def test_to_log_line(self):
        """Test formatting as log line."""
        entry = AuditEntry(
            timestamp=1704067200.0,  # 2024-01-01 00:00:00 UTC
            action="load",
            profile_label="test",
            target="playwright",
            details="15 cookies",
            success=True,
        )
        line = entry.to_log_line()

        assert "2024-01-01" in line
        assert "LOAD->playwright" in line
        assert "test" in line
        assert "OK" in line

    def test_from_log_line(self):
        """Test parsing from log line."""
        line = "[2024-01-01T12:00:00] SAVE->test-profile [15 cookies] - OK"
        entry = AuditEntry.from_log_line(line)

        assert entry is not None
        assert entry.action == "save"
        assert entry.profile_label == "test-profile"
        assert entry.details == "15 cookies"
        assert entry.success is True

    def test_from_log_line_failure(self):
        """Test parsing failed operation."""
        line = "[2024-01-01T12:00:00] LOAD->test - FAIL:not_found"
        entry = AuditEntry.from_log_line(line)

        assert entry is not None
        assert entry.action == "load"
        assert entry.success is False
        assert entry.error == "not_found"
