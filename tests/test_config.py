"""Tests for MCP Cookie Vault configuration."""

import pytest
import yaml
from pathlib import Path
import tempfile

from mcp_cookie_vault.config import SecurityConfig, create_default_config


class TestSecurityConfig:
    """Tests for SecurityConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SecurityConfig()

        assert config.allowlist == []
        assert config.denylist == []
        assert config.max_profiles_per_domain == 10
        assert config.require_confirm_for_reveal is True
        assert config.audit_logging is True

    def test_domain_allowed_empty_allowlist(self):
        """Test domain check with empty allowlist (all allowed)."""
        config = SecurityConfig()

        assert config.is_domain_allowed("example.com") is True
        assert config.is_domain_allowed("google.com") is True
        assert config.is_domain_allowed("sub.example.com") is True

    def test_domain_allowlist(self):
        """Test domain allowlist filtering."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                "security": {
                    "allowlist_domains": ["example.com", "*.google.com"],
                    "denylist_domains": [],
                }
            }, f)
            f.flush()

            config = SecurityConfig(f.name)

            assert config.is_domain_allowed("example.com") is True
            assert config.is_domain_allowed("sub.google.com") is True
            assert config.is_domain_allowed("google.com") is True
            assert config.is_domain_allowed("evil.com") is False

    def test_domain_denylist(self):
        """Test domain denylist filtering."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                "security": {
                    "allowlist_domains": [],
                    "denylist_domains": ["evil.com", "*.malware.org"],
                }
            }, f)
            f.flush()

            config = SecurityConfig(f.name)

            assert config.is_domain_allowed("example.com") is True
            assert config.is_domain_allowed("evil.com") is False
            assert config.is_domain_allowed("sub.malware.org") is False

    def test_wildcard_patterns(self):
        """Test wildcard domain patterns."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                "security": {
                    "allowlist_domains": ["*.example.com"],
                }
            }, f)
            f.flush()

            config = SecurityConfig(f.name)

            assert config.is_domain_allowed("sub.example.com") is True
            assert config.is_domain_allowed("deep.sub.example.com") is True
            assert config.is_domain_allowed("example.com") is True  # Base domain also matches
            assert config.is_domain_allowed("evil.com") is False

    def test_validate_profile_count(self):
        """Test profile count limit validation."""
        config = SecurityConfig()
        config.config["security"]["max_profiles_per_domain"] = 2

        # Create mock profiles
        class MockProfile:
            def __init__(self, domain):
                self.domain = domain

        profiles = [
            MockProfile("example.com"),
            MockProfile("example.com"),
        ]

        # At limit
        error = config.validate_profile_count("example.com", profiles)
        assert error is not None
        assert "limit reached" in error.lower()

        # Under limit
        error = config.validate_profile_count("other.com", profiles)
        assert error is None

    def test_save_and_load_config(self):
        """Test saving and loading configuration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"

            # Create and save
            config = SecurityConfig(str(config_path))
            config.config["security"]["max_profiles_per_domain"] = 5
            config.save()

            # Load
            loaded = SecurityConfig(str(config_path))

            assert loaded.max_profiles_per_domain == 5

    def test_create_default_config(self):
        """Test creating default configuration file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"

            result_path = create_default_config(str(config_path))

            assert result_path.exists()
            assert result_path == config_path

            # Verify content
            with open(result_path) as f:
                data = yaml.safe_load(f)

            assert "security" in data
            assert data["security"]["audit_logging"] is True
