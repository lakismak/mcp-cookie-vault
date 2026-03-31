"""Data models for MCP Cookie Vault."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import json


@dataclass
class Cookie:
    """
    Cookie model representing a single HTTP cookie.

    Attributes:
        name: Cookie name
        value: Cookie value
        domain: Domain the cookie belongs to
        path: Cookie path
        expires: Expiration timestamp (Unix seconds), None for session cookie
        http_only: Whether cookie is HTTP-only
        secure: Whether cookie requires secure connection
        same_site: SameSite policy (strict, lax, none)
    """

    name: str
    value: str
    domain: str
    path: str = "/"
    expires: Optional[float] = None
    http_only: bool = True
    secure: bool = True
    same_site: str = "lax"

    def is_expired(self) -> bool:
        """Check if cookie has expired."""
        if self.expires is None:
            return False
        return datetime.utcnow().timestamp() > self.expires

    def to_playwright(self) -> dict:
        """Convert to Playwright browser context format."""
        result = {
            "name": self.name,
            "value": self.value,
            "domain": self.domain,
            "path": self.path,
            "httpOnly": self.http_only,
            "secure": self.secure,
        }
        if self.expires:
            result["expires"] = self.expires
        if self.same_site != "lax":
            result["sameSite"] = self.same_site
        return result

    def to_requests(self) -> dict:
        """Convert to requests library format."""
        return {"name": self.name, "value": self.value}

    def to_netscape(self) -> str:
        """Convert to Netscape cookie format for browser import."""
        expires_str = str(int(self.expires)) if self.expires else "0"
        secure_str = "TRUE" if self.secure else "FALSE"
        return f"{self.domain}\tTRUE\t{self.path}\t{secure_str}\t{expires_str}\t{self.name}\t{self.value}"

    @classmethod
    def from_playwright(cls, data: dict) -> "Cookie":
        """Create from Playwright format."""
        return cls(
            name=data["name"],
            value=data["value"],
            domain=data.get("domain", ""),
            path=data.get("path", "/"),
            expires=data.get("expires"),
            http_only=data.get("httpOnly", True),
            secure=data.get("secure", True),
            same_site=data.get("sameSite", "lax"),
        )

    @classmethod
    def from_netscape_line(cls, line: str) -> Optional["Cookie"]:
        """Parse from Netscape format line."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        parts = line.split("\t")
        if len(parts) < 7:
            return None

        return cls(
            domain=parts[0],
            path=parts[2],
            secure=parts[3] == "TRUE",
            expires=int(parts[4]) if parts[4] != "0" else None,
            name=parts[5],
            value=parts[6],
        )


@dataclass
class SessionProfile:
    """
    Session profile - container for cookies and browser state.

    Attributes:
        label: Unique profile name (e.g., "youtube-main", "work-account-1")
        domain: Primary domain for this session
        cookies: List of cookies
        local_storage: localStorage key-value pairs
        session_storage: sessionStorage key-value pairs
        user_agent: Browser User Agent string
        viewport: Browser viewport dimensions
        created_at: Creation timestamp
        updated_at: Last update timestamp
        tags: Tags for categorization
        last_used: Last access timestamp
        access_count: Number of times loaded
        notes: Optional notes about this profile
    """

    label: str
    domain: str
    cookies: list[Cookie] = field(default_factory=list)
    local_storage: dict[str, str] = field(default_factory=dict)
    session_storage: dict[str, str] = field(default_factory=dict)
    user_agent: Optional[str] = None
    viewport: Optional[dict] = None
    created_at: float = field(default_factory=lambda: datetime.utcnow().timestamp())
    updated_at: float = field(default_factory=lambda: datetime.utcnow().timestamp())
    tags: list[str] = field(default_factory=list)
    last_used: Optional[float] = None
    access_count: int = 0
    notes: str = ""

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "label": self.label,
            "domain": self.domain,
            "cookies": [
                {
                    "name": c.name,
                    "value": c.value,
                    "domain": c.domain,
                    "path": c.path,
                    "expires": c.expires,
                    "http_only": c.http_only,
                    "secure": c.secure,
                    "same_site": c.same_site,
                }
                for c in self.cookies
            ],
            "local_storage": self.local_storage,
            "session_storage": self.session_storage,
            "user_agent": self.user_agent,
            "viewport": self.viewport,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "tags": self.tags,
            "last_used": self.last_used,
            "access_count": self.access_count,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SessionProfile":
        """Deserialize from dictionary."""
        cookies = [
            Cookie(
                name=c["name"],
                value=c["value"],
                domain=c["domain"],
                path=c["path"],
                expires=c.get("expires"),
                http_only=c.get("http_only", True),
                secure=c.get("secure", True),
                same_site=c.get("same_site", "lax"),
            )
            for c in data.get("cookies", [])
        ]
        return cls(
            label=data["label"],
            domain=data["domain"],
            cookies=cookies,
            local_storage=data.get("local_storage", {}),
            session_storage=data.get("session_storage", {}),
            user_agent=data.get("user_agent"),
            viewport=data.get("viewport"),
            created_at=data.get("created_at", datetime.utcnow().timestamp()),
            updated_at=data.get("updated_at", datetime.utcnow().timestamp()),
            tags=data.get("tags", []),
            last_used=data.get("last_used"),
            access_count=data.get("access_count", 0),
            notes=data.get("notes", ""),
        )

    def get_metadata(self) -> dict:
        """
        Get metadata WITHOUT sensitive cookie values.

        Safe to display - does not reveal cookie values.
        """
        return {
            "label": self.label,
            "domain": self.domain,
            "cookie_count": len(self.cookies),
            "cookies_summary": [
                {
                    "name": c.name,
                    "domain": c.domain,
                    "path": c.path,
                    "expires": datetime.fromtimestamp(c.expires).isoformat() if c.expires else "session",
                    "http_only": c.http_only,
                    "secure": c.secure,
                    "is_expired": c.is_expired(),
                }
                for c in self.cookies
            ],
            "local_storage_keys": list(self.local_storage.keys()),
            "local_storage_count": len(self.local_storage),
            "session_storage_keys": list(self.session_storage.keys()),
            "session_storage_count": len(self.session_storage),
            "user_agent": self.user_agent,
            "viewport": self.viewport,
            "tags": self.tags,
            "created_at": datetime.fromtimestamp(self.created_at).isoformat(),
            "updated_at": datetime.fromtimestamp(self.updated_at).isoformat(),
            "last_used": datetime.fromtimestamp(self.last_used).isoformat() if self.last_used else None,
            "access_count": self.access_count,
            "notes": self.notes,
        }


@dataclass
class AuditEntry:
    """
    Audit log entry for tracking operations.

    Attributes:
        timestamp: When the operation occurred
        action: Operation type (save, load, reveal, delete, export, import)
        profile_label: Profile name
        target: Target system (playwright, requests, etc.)
        details: Additional details
        success: Whether operation succeeded
        error: Error message if failed
    """

    timestamp: float
    action: str
    profile_label: str
    target: Optional[str] = None
    details: Optional[str] = None
    success: bool = True
    error: Optional[str] = None

    def to_log_line(self) -> str:
        """Format as log line."""
        ts = datetime.fromtimestamp(self.timestamp).isoformat()
        status = "OK" if self.success else f"FAIL:{self.error}"
        target = f"->{self.target}" if self.target else ""
        details = f" [{self.details}]" if self.details else ""
        return f"[{ts}] {self.action.upper()}{target} {self.profile_label}{details} - {status}"

    @classmethod
    def from_log_line(cls, line: str) -> Optional["AuditEntry"]:
        """Parse from log line."""
        try:
            ts_end = line.index("]")
            ts = datetime.fromisoformat(line[1:ts_end]).timestamp()

            rest = line[ts_end + 2 :].strip()
            parts = rest.split(" - ")
            if len(parts) != 2:
                return None

            action_part = parts[0]
            status = parts[1]

            if "->" in action_part:
                action, rest_target = action_part.split("->", 1)
                target_profile = rest_target.split(" ", 1)
                target = target_profile[0]
                profile = target_profile[1].split("[")[0].strip() if "[" in target_profile[1] else target_profile[1].strip()
                details = None
                if "[" in rest_target and "]" in rest_target:
                    details = rest_target.split("[")[1].split("]")[0]
            else:
                action = action_part.split()[0]
                profile = action_part.split()[1] if len(action_part.split()) > 1 else ""
                target = None
                details = None

            return cls(
                timestamp=ts,
                action=action.lower(),
                profile_label=profile,
                target=target,
                details=details,
                success=status == "OK",
                error=status.replace("FAIL:", "") if status.startswith("FAIL:") else None,
            )
        except Exception:
            return None
