"""MCP Cookie Vault Server - Secure session management for MCP."""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from .models import SessionProfile, Cookie
from .storage import EncryptedStorage, AuditLog
from .config import SecurityConfig, create_default_config


# Initialize MCP server
mcp = FastMCP(
    "Cookie Vault",
    dependencies=["cryptography", "keyring", "pyyaml"],
)

# Global instances (lazy initialization)
_storage: Optional[EncryptedStorage] = None
_audit_log: Optional[AuditLog] = None
_config: Optional[SecurityConfig] = None


def get_storage() -> EncryptedStorage:
    """Get storage instance (lazy initialization)."""
    global _storage
    if _storage is None:
        _storage = EncryptedStorage()
    return _storage


def get_audit_log() -> AuditLog:
    """Get audit log instance (lazy initialization)."""
    global _audit_log
    if _audit_log is None:
        _audit_log = AuditLog()
    return _audit_log


def get_config() -> SecurityConfig:
    """Get configuration instance (lazy initialization)."""
    global _config
    if _config is None:
        _config = SecurityConfig()
    return _config


# =============================================================================
# TOOLS - Safe operations (metadata only, no decryption of values)
# =============================================================================


@mcp.tool()
async def list_cookie_sets() -> list[dict]:
    """
    List all saved session profiles.

    Returns only metadata WITHOUT cookie values.
    Safe operation - can be called without restrictions.

    Returns:
        List of profiles with metadata
    """
    storage = get_storage()
    profiles = await storage.list_profiles()

    return [p.get_metadata() for p in profiles]


@mcp.tool()
async def get_cookie_metadata(label: str) -> dict:
    """
    Get metadata for a specific profile.

    Returns profile information WITHOUT cookie values.
    Safe operation.

    Args:
        label: Profile name (e.g., "youtube-main")

    Returns:
        Profile metadata
    """
    storage = get_storage()
    metadata = await storage.get_metadata(label)

    if metadata is None:
        return {"error": f"Profile '{label}' not found"}

    # Log access
    if get_config().audit_logging:
        await get_audit_log().log("metadata_view", label)

    return metadata


@mcp.tool()
async def search_profiles(
    domain: Optional[str] = None,
    tag: Optional[str] = None,
) -> list[dict]:
    """
    Search profiles by filter.

    Args:
        domain: Filter by domain
        tag: Filter by tag

    Returns:
        List of matching profiles
    """
    storage = get_storage()
    profiles = await storage.list_profiles()

    result = []
    for p in profiles:
        if domain and domain.lower() not in p.domain.lower():
            continue
        if tag and tag not in p.tags:
            continue
        result.append(p.get_metadata())

    return result


# =============================================================================
# TOOLS - Save/Load operations
# =============================================================================


@mcp.tool()
async def save_cookies(
    label: str,
    domain: str,
    cookies_json: str,
    local_storage_json: Optional[str] = None,
    session_storage_json: Optional[str] = None,
    user_agent: Optional[str] = None,
    tags: Optional[list[str]] = None,
    notes: str = "",
) -> str:
    """
    Save cookies and session state.

    Args:
        label: Unique profile name (e.g., "youtube-main", "work-account-1")
        domain: Primary domain for the session
        cookies_json: JSON string with cookie list:
                     [{"name": "...", "value": "...", "domain": "...", ...}, ...]
        local_storage_json: JSON string with localStorage (optional)
        session_storage_json: JSON string with sessionStorage (optional)
        user_agent: Browser User Agent string (optional)
        tags: Tags for categorization (e.g., ["work", "social"])
        notes: Notes about the profile

    Returns:
        Operation status

    Example cookies_json:
        [
            {"name": "session_id", "value": "abc123", "domain": ".example.com"},
            {"name": "user_token", "value": "xyz789", "domain": ".example.com"}
        ]
    """
    storage = get_storage()
    config = get_config()

    # Domain check
    if not config.is_domain_allowed(domain):
        error_msg = f"Domain '{domain}' is not allowed by configuration"
        if config.audit_logging:
            await get_audit_log().log("save", label, error=error_msg)
        return f"❌ {error_msg}"

    # Limit check
    existing = await storage.list_profiles()
    limit_error = config.validate_profile_count(domain, existing)
    if limit_error:
        if config.audit_logging:
            await get_audit_log().log("save", label, error=limit_error)
        return f"❌ {limit_error}"

    # Parse cookies
    try:
        cookies_data = json.loads(cookies_json)
        cookies = [Cookie(**c) if isinstance(c, dict) else Cookie.from_playwright(c) for c in cookies_data]
    except json.JSONDecodeError as e:
        return f"❌ Error parsing cookies_json: {e}"
    except Exception as e:
        return f"❌ Error creating cookies: {e}"

    # Parse localStorage
    local_storage = {}
    if local_storage_json:
        try:
            local_storage = json.loads(local_storage_json)
        except json.JSONDecodeError as e:
            return f"❌ Error parsing local_storage_json: {e}"

    # Parse sessionStorage
    session_storage = {}
    if session_storage_json:
        try:
            session_storage = json.loads(session_storage_json)
        except json.JSONDecodeError as e:
            return f"❌ Error parsing session_storage_json: {e}"

    # Create profile
    profile = SessionProfile(
        label=label,
        domain=domain,
        cookies=cookies,
        local_storage=local_storage,
        session_storage=session_storage,
        user_agent=user_agent,
        tags=tags or [],
        notes=notes,
    )

    # Save
    await storage.save_profile(profile)

    if config.audit_logging:
        await get_audit_log().log("save", label, details=f"{len(cookies)} cookies")

    return f"✅ Profile '{label}' saved ({len(cookies)} cookies, {len(local_storage)} localStorage keys)"


@mcp.tool()
async def load_cookies(
    label: str,
    target: str = "json",
    confirm: bool = False,
) -> dict:
    """
    Load cookies from profile.

    ⚠️ Returns cookie values - sensitive operation!

    Args:
        label: Profile name to load
        target: Output format:
                - "json" - raw JSON (default)
                - "playwright" - Playwright format
                - "requests" - requests library format
                - "netscape" - Netscape format for browser import
        confirm: Confirmation required for security

    Returns:
        Cookies in requested format
    """
    storage = get_storage()
    config = get_config()

    # Check existence
    profile = await storage.load_profile(label)
    if profile is None:
        if config.audit_logging:
            await get_audit_log().log("load", label, target=target, error="not_found")
        return {"error": f"Profile '{label}' not found"}

    # Check confirmation
    if config.require_confirm_for_reveal and not confirm:
        return {
            "error": "Confirmation required (confirm=true) to load cookies",
            "hint": "This is a sensitive operation - please confirm"
        }

    # Update access stats
    await storage.update_access(label)

    # Format output
    if target == "playwright":
        result = {
            "format": "playwright",
            "cookies": [c.to_playwright() for c in profile.cookies],
        }
    elif target == "requests":
        result = {
            "format": "requests",
            "cookies": {c.name: c.value for c in profile.cookies},
        }
    elif target == "netscape":
        lines = ["# Netscape Cookie File", f"# Domain: {profile.domain}", ""]
        for c in profile.cookies:
            lines.append(c.to_netscape())
        result = {
            "format": "netscape",
            "content": "\n".join(lines),
        }
    else:  # json
        result = {
            "format": "json",
            "profile": label,
            "domain": profile.domain,
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
                for c in profile.cookies
            ],
            "local_storage": profile.local_storage,
            "session_storage": profile.session_storage,
            "user_agent": profile.user_agent,
        }

    if config.audit_logging:
        await get_audit_log().log("load", label, target=target)

    return result


@mcp.tool()
async def delete_cookie_set(label: str, confirm: bool = False) -> str:
    """
    Delete session profile.

    ⚠️ Irreversible operation!

    Args:
        label: Profile name to delete
        confirm: Confirmation required

    Returns:
        Operation status
    """
    storage = get_storage()
    config = get_config()

    if not confirm:
        return "❌ Confirmation required (confirm=true) to delete profile"

    deleted = await storage.delete_profile(label)

    if config.audit_logging:
        await get_audit_log().log("delete", label, success=deleted)

    if deleted:
        return f"✅ Profile '{label}' deleted"
    else:
        return f"❌ Profile '{label}' not found"


@mcp.tool()
async def clear_domain_cookies(domain: str, confirm: bool = False) -> str:
    """
    Delete all profiles for a domain.

    ⚠️ Irreversible operation!

    Args:
        domain: Domain to clear
        confirm: Confirmation required

    Returns:
        Number of deleted profiles
    """
    storage = get_storage()
    config = get_config()

    if not confirm:
        return "❌ Confirmation required (confirm=true) to clear domain"

    profiles = await storage.list_profiles()
    to_delete = [p for p in profiles if p.domain == domain]

    count = 0
    for p in to_delete:
        if await storage.delete_profile(p.label):
            count += 1
            if config.audit_logging:
                await get_audit_log().log("delete", p.label, details=f"domain_clear:{domain}")

    return f"✅ Deleted {count} profiles for domain '{domain}'"


# =============================================================================
# TOOLS - Export/Import
# =============================================================================


@mcp.tool()
async def export_cookie_set(
    label: str,
    format: str = "json",
    confirm: bool = False,
) -> dict:
    """
    Export profile to file.

    Args:
        label: Profile name to export
        format: Export format:
                - "json" - JSON file
                - "netscape" - Netscape format for browser import
        confirm: Confirmation required

    Returns:
        File path and content
    """
    storage = get_storage()
    config = get_config()

    if config.require_confirm_for_export and not confirm:
        return {"error": "Confirmation required (confirm=true) for export"}

    profile = await storage.load_profile(label)
    if profile is None:
        return {"error": f"Profile '{label}' not found"}

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if format == "netscape":
        filename = f"cookies_{label}_{timestamp}.txt"
        lines = ["# Netscape Cookie File", f"# Exported from MCP Cookie Vault", f"# Profile: {label}", ""]
        for c in profile.cookies:
            lines.append(c.to_netscape())
        content = "\n".join(lines)
    else:  # json
        filename = f"cookies_{label}_{timestamp}.json"
        content = json.dumps(profile.to_dict(), indent=2, ensure_ascii=False)

    filepath = Path.cwd() / filename
    filepath.write_text(content, encoding="utf-8")

    if config.audit_logging:
        await get_audit_log().log("export", label, target=format, details=str(filepath))

    return {
        "filename": filename,
        "filepath": str(filepath.absolute()),
        "format": format,
        "cookie_count": len(profile.cookies),
    }


@mcp.tool()
async def import_cookie_set(
    label: str,
    content: Optional[str] = None,
    filepath: Optional[str] = None,
    format: str = "json",
    domain: Optional[str] = None,
    tags: Optional[list[str]] = None,
) -> str:
    """
    Import profile from file or string.

    Args:
        label: Name for new profile
        content: JSON or Netscape string to import
        filepath: Path to import file (alternative to content)
        format: Data format: "json" or "netscape"
        domain: Domain for profile (required for netscape)
        tags: Tags for profile

    Returns:
        Import status
    """
    storage = get_storage()
    config = get_config()

    # Check if profile exists
    if await storage.profile_exists(label):
        return f"❌ Profile '{label}' already exists"

    # Read data
    if filepath:
        try:
            data = Path(filepath).read_text(encoding="utf-8")
        except Exception as e:
            return f"❌ Error reading file: {e}"
    elif content:
        data = content
    else:
        return "❌ content or filepath required"

    # Parse
    try:
        if format == "netscape":
            if not domain:
                return "❌ domain required for Netscape format"

            cookies = []
            for line in data.split("\n"):
                cookie = Cookie.from_netscape_line(line)
                if cookie:
                    cookies.append(cookie)

            profile = SessionProfile(
                label=label,
                domain=domain,
                cookies=cookies,
                tags=tags or [],
            )
        else:  # json
            json_data = json.loads(data)
            profile = SessionProfile.from_dict(json_data)
            profile.label = label  # Override name
            if tags:
                profile.tags = tags
    except Exception as e:
        return f"❌ Parse error: {e}"

    # Domain check
    if not config.is_domain_allowed(profile.domain):
        return f"❌ Domain '{profile.domain}' not allowed by configuration"

    # Save
    await storage.save_profile(profile)

    if config.audit_logging:
        await get_audit_log().log("import", label, details=f"{len(profile.cookies)} cookies")

    return f"✅ Imported profile '{label}' ({len(profile.cookies)} cookies)"


# =============================================================================
# TOOLS - Session management
# =============================================================================


@mcp.tool()
async def rotate_session_label(
    old_label: str,
    new_label: str,
    confirm: bool = False,
) -> str:
    """
    Rename profile (versioning).

    Args:
        old_label: Current profile name
        new_label: New profile name
        confirm: Confirmation required

    Returns:
        Operation status
    """
    storage = get_storage()
    config = get_config()

    if not confirm:
        return "❌ Confirmation required (confirm=true) for rename"

    profile = await storage.load_profile(old_label)
    if profile is None:
        return f"❌ Profile '{old_label}' not found"

    if await storage.profile_exists(new_label):
        return f"❌ Profile '{new_label}' already exists"

    # Delete old, save with new name
    profile.label = new_label
    await storage.save_profile(profile)
    await storage.delete_profile(old_label)

    if config.audit_logging:
        await get_audit_log().log("rename", old_label, target=new_label)

    return f"✅ Profile renamed: '{old_label}' → '{new_label}'"


@mcp.tool()
async def get_audit_log_entries(
    limit: int = 50,
    profile_label: Optional[str] = None,
    action: Optional[str] = None,
) -> list[dict]:
    """
    Get audit log entries.

    Args:
        limit: Maximum entries to return
        profile_label: Filter by profile
        action: Filter by action type

    Returns:
        List of log entries
    """
    audit = get_audit_log()

    if profile_label or action:
        entries = await audit.search(profile_label=profile_label, action=action)
    else:
        entries = await audit.get_entries(limit=limit)

    return [
        {
            "timestamp": datetime.fromtimestamp(e.timestamp).isoformat(),
            "action": e.action,
            "profile": e.profile_label,
            "target": e.target,
            "details": e.details,
            "success": e.success,
            "error": e.error,
        }
        for e in entries
    ]


@mcp.tool()
async def reveal_cookies(
    label: str,
    confirm: bool = False,
) -> dict:
    """
    ⚠️ Show ALL cookie values for profile.

    Critically sensitive operation - use with caution!

    Args:
        label: Profile name
        confirm: Must be True for confirmation

    Returns:
        Full profile data with all values
    """
    storage = get_storage()
    config = get_config()

    if not confirm:
        return {
            "error": "Confirmation required (confirm=true)",
            "warning": "This will reveal ALL secret cookie values!"
        }

    profile = await storage.load_profile(label)
    if profile is None:
        return {"error": f"Profile '{label}' not found"}

    if config.audit_logging:
        await get_audit_log().log("reveal", label, details="FULL_REVEAL")

    return {
        "warning": "⚠️ Sensitive data revealed",
        "profile": profile.get_metadata(),
        "cookies_full": [c.__dict__ for c in profile.cookies],
        "local_storage": profile.local_storage,
        "session_storage": profile.session_storage,
    }


# =============================================================================
# RESOURCES - State reading
# =============================================================================


@mcp.resource("cookie-vault://profiles")
async def list_profiles_resource() -> str:
    """List all profiles (quick view)."""
    profiles = await list_cookie_sets()

    if not profiles:
        return "No saved profiles"

    lines = ["=== MCP Cookie Vault Profiles ===", ""]
    for p in profiles:
        expired_count = sum(1 for c in p.get("cookies_summary", []) if c.get("is_expired"))
        lines.append(f"📦 {p['label']}")
        lines.append(f"   Domain: {p['domain']}")
        lines.append(f"   Cookies: {p['cookie_count']} (expired: {expired_count})")
        lines.append(f"   Tags: {', '.join(p['tags']) if p['tags'] else '-'}")
        lines.append(f"   Created: {p['created_at']}")
        lines.append("")

    return "\n".join(lines)


@mcp.resource("cookie-vault://profile/{label}")
async def profile_resource(label: str) -> str:
    """Detailed profile information."""
    metadata = await get_cookie_metadata(label)

    if "error" in metadata:
        return f"❌ {metadata['error']}"

    lines = [
        f"=== Profile: {metadata['label']} ===",
        f"Domain: {metadata['domain']}",
        f"Cookies: {metadata['cookie_count']}",
        f"LocalStorage: {metadata['local_storage_count']} keys",
        f"Tags: {', '.join(metadata['tags']) if metadata['tags'] else '-'}",
        f"Created: {metadata['created_at']}",
        f"Last Used: {metadata['last_used'] or 'Never'}",
        f"Access Count: {metadata['access_count']}",
        "",
        "Cookies Summary:",
    ]

    for c in metadata.get("cookies_summary", []):
        status = "⚠️ EXPIRED" if c.get("is_expired") else "✓"
        lines.append(f"  {status} {c['name']} ({c['domain']})")

    return "\n".join(lines)


@mcp.resource("cookie-vault://audit-log")
async def audit_log_resource() -> str:
    """Recent audit log entries."""
    entries = await get_audit_log_entries(limit=20)

    if not entries:
        return "Audit log is empty"

    lines = ["=== Audit Log (last 20 entries) ===", ""]
    for e in entries:
        status = "✓" if e["success"] else "❌"
        target = f"→{e['target']}" if e["target"] else ""
        lines.append(f"{status} [{e['timestamp']}] {e['action'].upper()}{target} {e['profile']}")
        if e.get("details"):
            lines.append(f"     Details: {e['details']}")
        if e.get("error"):
            lines.append(f"     Error: {e['error']}")

    return "\n".join(lines)


# =============================================================================
# Server entry point
# =============================================================================


def main():
    """Entry point for running the server."""
    # Create default config if not exists
    config_path = Path.home() / ".mcp-cookie-vault" / "config.yaml"
    if not config_path.exists():
        create_default_config(str(config_path))

    mcp.run()


if __name__ == "__main__":
    main()
