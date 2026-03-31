"""MCP Cookie Vault - Secure cookie and session storage for MCP."""

from .models import Cookie, SessionProfile, AuditEntry
from .storage import EncryptedStorage, AuditLog
from .config import SecurityConfig, create_default_config

__version__ = "1.0.0"
__all__ = [
    "Cookie",
    "SessionProfile",
    "AuditEntry",
    "EncryptedStorage",
    "AuditLog",
    "SecurityConfig",
    "create_default_config",
]
