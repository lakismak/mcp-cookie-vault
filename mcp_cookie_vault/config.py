"""Configuration and security settings for MCP Cookie Vault."""

import yaml
from pathlib import Path
from typing import Optional, List
from fnmatch import fnmatch


class SecurityConfig:
    """
    Security configuration for MCP Cookie Vault.

    Manages domain allowlists, denylists, rate limits, and confirmation requirements.

    Security features:
    - Domain allowlist/denylist filtering
    - Maximum profiles per domain limit
    - Confirmation requirements for sensitive operations
    - Audit logging toggle
    """

    DEFAULT_CONFIG = {
        "security": {
            "allowlist_domains": [],  # Empty = all domains allowed
            "denylist_domains": [],
            "max_profiles_per_domain": 10,
            "require_confirm_for_reveal": True,
            "require_confirm_for_export": False,
            "max_export_profiles": 5,
            "audit_logging": True,
        },
        "storage": {
            "vault_path": None,  # Default: ~/.mcp-cookie-vault
            "encryption": True,
        },
        "ui": {
            "hide_cookie_values_by_default": True,
            "show_expired_in_list": True,
        },
    }

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration.

        Args:
            config_path: Path to YAML configuration file
        """
        self.config_path = Path(config_path) if config_path else self._default_config_path()
        self.config = self._load_config()

    def _default_config_path(self) -> Path:
        """Get default configuration path."""
        return Path.home() / ".mcp-cookie-vault" / "config.yaml"

    def _load_config(self) -> dict:
        """Load configuration from file or use defaults."""
        if self.config_path.exists():
            with open(self.config_path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
            return self._deep_merge(self.DEFAULT_CONFIG, loaded)
        return self.DEFAULT_CONFIG.copy()

    def _deep_merge(self, base: dict, override: dict) -> dict:
        """Deep merge two dictionaries."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def save(self) -> None:
        """Save configuration to file."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(self.config, f, default_flow_style=False, allow_unicode=True)

    @property
    def allowlist(self) -> List[str]:
        """Get domain allowlist."""
        return self.config.get("security", {}).get("allowlist_domains", [])

    @property
    def denylist(self) -> List[str]:
        """Get domain denylist."""
        return self.config.get("security", {}).get("denylist_domains", [])

    @property
    def max_profiles_per_domain(self) -> int:
        """Get maximum profiles per domain limit."""
        return self.config.get("security", {}).get("max_profiles_per_domain", 10)

    @property
    def require_confirm_for_reveal(self) -> bool:
        """Check if confirmation required for reveal operation."""
        return self.config.get("security", {}).get("require_confirm_for_reveal", True)

    @property
    def require_confirm_for_export(self) -> bool:
        """Check if confirmation required for export operation."""
        return self.config.get("security", {}).get("require_confirm_for_export", False)

    @property
    def max_export_profiles(self) -> int:
        """Get maximum profiles that can be exported at once."""
        return self.config.get("security", {}).get("max_export_profiles", 5)

    @property
    def audit_logging(self) -> bool:
        """Check if audit logging is enabled."""
        return self.config.get("security", {}).get("audit_logging", True)

    @property
    def hide_cookie_values_by_default(self) -> bool:
        """Check if cookie values should be hidden by default."""
        return self.config.get("ui", {}).get("hide_cookie_values_by_default", True)

    def is_domain_allowed(self, domain: str) -> bool:
        """
        Check if a domain is allowed.

        Args:
            domain: Domain to check

        Returns:
            True if domain is allowed
        """
        # Check denylist first
        for pattern in self.denylist:
            if self._domain_matches(domain, pattern):
                return False

        # If allowlist is empty, all domains are allowed (except denylist)
        if not self.allowlist:
            return True

        # Check allowlist
        for pattern in self.allowlist:
            if self._domain_matches(domain, pattern):
                return True

        return False

    def _domain_matches(self, domain: str, pattern: str) -> bool:
        """Check if domain matches pattern (supports wildcards)."""
        if pattern.startswith("*."):
            base = pattern[2:]
            return domain == base or domain.endswith("." + base)
        return domain == pattern or fnmatch(domain, pattern)

    def validate_profile_count(self, domain: str, existing_profiles: list) -> Optional[str]:
        """
        Validate profile count limit for domain.

        Args:
            domain: Domain to check
            existing_profiles: List of existing profiles

        Returns:
            Error message if limit exceeded, None otherwise
        """
        count = sum(1 for p in existing_profiles if p.domain == domain)
        if count >= self.max_profiles_per_domain:
            return f"Profile limit reached for domain {domain} (max {self.max_profiles_per_domain})"
        return None


def create_default_config(config_path: Optional[str] = None) -> Path:
    """
    Create default configuration file.

    Args:
        config_path: Optional path for config file

    Returns:
        Path to created configuration file
    """
    config = SecurityConfig(config_path)
    config.save()
    return config.config_path
