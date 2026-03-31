# MCP Cookie Vault 🔐

**Secure cookie and session storage for MCP (Model Context Protocol)**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/mcp-cookie-vault.svg)](https://badge.fury.io/py/mcp-cookie-vault)

MCP Cookie Vault is a secure MCP server for managing browser cookies, localStorage, and sessionStorage with a focus on **security** and **privacy**. This is not a "cookie stealer" — it's a legitimate **session state manager** for browser automation and multi-account workflows.

---

## 📋 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [For AI Assistants](#-for-ai-assistants)
- [Tools API](#-tools-api)
- [Security](#-security)
- [Configuration](#-configuration)
- [Examples](#-examples)
- [Playwright Integration](#-playwright-integration)
- [FAQ](#-faq)

---

## ✨ Features

| Category | Features |
|----------|----------|
| **Storage** | Cookies + localStorage + sessionStorage + User Agent |
| **Security** | Fernet encryption, OS keyring, audit log, domain allowlist |
| **Management** | Profile tagging, versioning, search |
| **Export/Import** | JSON, Netscape format (browser import) |
| **Formats** | Playwright, requests, raw JSON, Netscape |

### Key Concepts

- **Session Profile** — Named container for cookies and session state
- **Metadata by Default** — Cookie values hidden without explicit confirmation
- **Audit Logging** — All operations logged for traceability
- **Encryption at Rest** — Master key stored in OS keyring

---

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/lakismak/mcp-cookie-vault.git
cd mcp-cookie-vault

# Install with pip
pip install -e .

# Or with uv (recommended)
uv pip install -e .
```

### Requirements

- Python 3.10+
- `mcp` — Model Context Protocol SDK
- `cryptography` — Data encryption
- `keyring` — Master key storage in OS keyring
- `pyyaml` — Configuration

### First Run

```bash
# Run via MCP
mcp dev mcp_cookie_vault/server.py

# Or directly
python -m mcp_cookie_vault
```

On first run:
- `~/.mcp-cookie-vault/` — Vault directory created
- `~/.mcp-cookie-vault/config.yaml` — Configuration file
- Master key stored in system keyring

---

## 🤖 For AI Assistants

This section is for AI models (Claude, GPT, etc.) working via MCP.

### When to Use Cookie Vault

| Scenario | Use |
|----------|-----|
| Save session after manual login | ✅ `save_cookies` |
| Restore session for automation | ✅ `load_cookies` |
| Check available profiles | ✅ `list_cookie_sets` |
| View profile details | ✅ `get_cookie_metadata` |
| Delete old profile | ✅ `delete_cookie_set` |
| Export for backup | ✅ `export_cookie_set` |

### ⚠️ Security Rules

1. **Never show cookie values without explicit need**
   - Use `get_cookie_metadata` instead of `reveal_cookies`
   - `load_cookies` requires `confirm=true` — this is protection

2. **Always check profile exists before operations**
   ```
   1. First: list_cookie_sets() or get_cookie_metadata(label)
   2. Then: load_cookies(label, confirm=true)
   ```

3. **Use tags for categorization**
   ```
   tags: ["work", "social", "shopping", "test-account"]
   ```

4. **Use descriptive profile names**
   ```
   ✅ "youtube-main-account"
   ✅ "google-work-personal"
   ❌ "profile1", "temp"
   ```

### 📋 Typical AI Flow

```
┌─────────────────────────────────────────────────────────────┐
│ Flow: Save session after manual login                       │
├─────────────────────────────────────────────────────────────┤
│ 1. User manually logs in browser                            │
│ 2. Extracts cookies (DevTools/extension)                    │
│ 3. Calls: save_cookies(                                     │
│      label="site-account-name",                             │
│      domain="example.com",                                  │
│      cookies_json="[...]",                                  │
│      tags=["category"]                                      │
│    )                                                        │
│ 4. Profile saved in encrypted vault                         │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Flow: Restore session for automation                        │
├─────────────────────────────────────────────────────────────┤
│ 1. Check: get_cookie_metadata("site-account-name")          │
│ 2. Load: load_cookies(                                      │
│      label="site-account-name",                             │
│      target="playwright",                                   │
│      confirm=true                                           │
│    )                                                        │
│ 3. Apply cookies to Playwright context                      │
│ 4. Continue automation without re-login                     │
└─────────────────────────────────────────────────────────────┘
```

### 🔧 Data Formats

#### cookies_json for save_cookies

```json
[
  {
    "name": "session_id",
    "value": "abc123xyz",
    "domain": ".example.com",
    "path": "/",
    "expires": 1735689600,
    "http_only": true,
    "secure": true,
    "same_site": "lax"
  }
]
```

#### local_storage_json

```json
{
  "user_preferences": "{\"theme\":\"dark\"}",
  "auth_token": "bearer_xyz"
}
```

---

## 🛠️ Tools API

### Safe Operations (no confirm required)

| Tool | Description | Example |
|------|-------------|---------|
| `list_cookie_sets` | List all profiles (metadata) | `list_cookie_sets()` |
| `get_cookie_metadata` | Profile details without values | `get_cookie_metadata("youtube-main")` |
| `search_profiles` | Search by domain/tag | `search_profiles(domain="google.com")` |

### Sensitive Operations (require confirm)

| Tool | Description | Example |
|------|-------------|---------|
| `save_cookies` | Save session | `save_cookies("label", "domain.com", cookies_json="...")` |
| `load_cookies` | Load cookies | `load_cookies("label", target="playwright", confirm=true)` |
| `delete_cookie_set` | Delete profile | `delete_cookie_set("label", confirm=true)` |
| `reveal_cookies` | Show all values | `reveal_cookies("label", confirm=true)` |

### Export/Import

| Tool | Description | Example |
|------|-------------|---------|
| `export_cookie_set` | Export to file | `export_cookie_set("label", format="json", confirm=true)` |
| `import_cookie_set` | Import from file | `import_cookie_set("new-label", filepath="cookies.json")` |

### Management

| Tool | Description | Example |
|------|-------------|---------|
| `rotate_session_label` | Rename profile | `rotate_session_label("old", "new", confirm=true)` |
| `clear_domain_cookies` | Clear domain | `clear_domain_cookies("example.com", confirm=true)` |
| `get_audit_log_entries` | View audit log | `get_audit_log_entries(limit=50)` |

---

## 📖 Resources

MCP resources for reading state:

| Resource URI | Description |
|--------------|----------|
| `cookie-vault://profiles` | List all profiles |
| `cookie-vault://profile/{label}` | Specific profile details |
| `cookie-vault://audit-log` | Recent audit log entries |

---

## 🔐 Security

### Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     MCP Cookie Vault                        │
├─────────────────────────────────────────────────────────────┤
│  System Keyring (OS)                                        │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  master_key (Fernet key, 256-bit)                     │  │
│  └───────────────────────────────────────────────────────┘  │
│                          ↓                                  │
│  Encrypted Storage (~/.mcp-cookie-vault/)                   │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  profile1.json.enc  ← encrypted data                  │  │
│  │  profile2.json.enc                                    │  │
│  │  audit.log         ← operation logs                   │  │
│  │  config.yaml       ← configuration                    │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Security Principles

1. **Metadata by default** — Cookie values hidden in normal operations
2. **Explicit confirm** — Sensitive operations require `confirm=true`
3. **Audit logging** — All operations recorded
4. **Domain allowlist** — Can restrict to specific domains
5. **Encryption at rest** — Data encrypted on disk

### Audit Log

All operations logged to `~/.mcp-cookie-vault/audit.log`:

```
[2024-01-15T10:30:00] SAVE youtube-main [15 cookies] - OK
[2024-01-15T10:35:00] LOAD->playwright youtube-main - OK
[2024-01-15T10:40:00] REVEAL youtube-main [FULL_REVEAL] - OK
[2024-01-15T11:00:00] DELETE temp-profile - OK
```

View via MCP:
```python
get_audit_log_entries(limit=50)
get_audit_log_entries(profile_label="youtube-main", action="load")
```

---

## ⚙️ Configuration

### Configuration File

`~/.mcp-cookie-vault/config.yaml`:

```yaml
security:
  # Allowed domains (empty = all allowed)
  allowlist_domains:
    - "google.com"
    - "*.youtube.com"
    - "api.example.com"

  # Denied domains
  denylist_domains:
    - "bank.com"
    - "sensitive-site.org"

  # Max profiles per domain
  max_profiles_per_domain: 10

  # Require confirm for reveal_cookies
  require_confirm_for_reveal: true

  # Require confirm for export
  require_confirm_for_export: false

  # Max profiles per export
  max_export_profiles: 5

  # Enable audit logging
  audit_logging: true

ui:
  # Hide cookie values by default
  hide_cookie_values_by_default: true

  # Show expired cookies in list
  show_expired_in_list: true
```

### Create Default Config

```python
from mcp_cookie_vault import create_default_config

# Create default config
create_default_config()
```

---

## 📚 Examples

### Example 1: Save YouTube Session

```python
# After manual YouTube login, extract cookies
cookies_json = '''
[
  {"name": "LOGIN_INFO", "value": "AFmmF2sw...", "domain": ".youtube.com"},
  {"name": "SIDCC", "value": "AKEyXzWq...", "domain": ".google.com"},
  {"name": "HSID", "value": "A1B2C3...", "domain": ".google.com"}
]
'''

local_storage = '''
{"yt-remote-device-id": "browser-123", "yt-remote-session-name": "My Session"}
'''

save_cookies(
    label="youtube-main-account",
    domain="youtube.com",
    cookies_json=cookies_json,
    local_storage_json=local_storage,
    tags=["google", "video", "personal"],
    notes="Main YouTube account"
)
```

### Example 2: Load Session to Playwright

```python
# Check profile exists
metadata = get_cookie_metadata("youtube-main-account")
if "error" in metadata:
    return f"Profile not found: {metadata['error']}"

# Load cookies
result = load_cookies(
    label="youtube-main-account",
    target="playwright",
    confirm=true
)

# Apply in Playwright
from playwright.asyncio import async_playwright

async with async_playwright() as p:
    browser = await p.chromium.launch()
    context = await browser.new_context()
    await context.add_cookies(result["cookies"])

    # Restore localStorage
    page = await context.new_page()
    await page.goto("https://youtube.com")
    for key, value in result.get("local_storage", {}).items():
        await page.evaluate(f"localStorage.setItem('{key}', '{value}')")
```

### Example 3: Multi-Account Workflow

```python
# Save multiple accounts
save_cookies("google-work-1", "google.com", work_cookies_1, tags=["work"])
save_cookies("google-work-2", "google.com", work_cookies_2, tags=["work"])
save_cookies("google-personal", "google.com", personal_cookies, tags=["personal"])

# Search by tag
work_profiles = search_profiles(tag="work")
# Returns: ["google-work-1", "google-work-2"]

# Rename on rotation
rotate_session_label("google-work-1", "google-work-1-archived", confirm=true)
save_cookies("google-work-1", "google.com", new_cookies, tags=["work"])
```

### Example 4: Export for Backup

```python
# Export all work profiles
profiles = search_profiles(tag="work")

for profile in profiles:
    result = export_cookie_set(
        label=profile["label"],
        format="json",
        confirm=true
    )
    print(f"Exported {profile['label']} to {result['filepath']}")
```

---

## 🎭 Playwright Integration

### Helper: Save from Playwright

```python
from playwright.asyncio import BrowserContext
import json

async def save_from_playwright(
    context: BrowserContext,
    label: str,
    domain: str,
    tags: list[str] = None,
):
    """Save session from Playwright context."""

    # Extract cookies
    cookies = await context.cookies()

    # Extract localStorage
    page = await context.new_page()
    await page.goto(f"https://{domain}")

    local_storage = await page.evaluate("() => { ...localStorage }")
    session_storage = await page.evaluate("() => { ...sessionStorage }")

    user_agent = await context.evaluate("navigator.userAgent")

    # Save via MCP
    return save_cookies(
        label=label,
        domain=domain,
        cookies_json=json.dumps(cookies),
        local_storage_json=json.dumps(local_storage),
        session_storage_json=json.dumps(session_storage),
        user_agent=user_agent,
        tags=tags or []
    )
```

### Helper: Load to Playwright

```python
async def load_to_playwright(
    context: BrowserContext,
    label: str,
):
    """Load session to Playwright context."""

    # Load via MCP
    result = load_cookies(label=label, target="playwright", confirm=true)

    if "error" in result:
        raise ValueError(result["error"])

    # Apply cookies
    await context.add_cookies(result["cookies"])

    # Apply localStorage
    page = await context.new_page()
    await page.goto("about:blank")

    for key, value in result.get("local_storage", {}).items():
        await page.evaluate(f"localStorage.setItem('{key}', '{value}')")

    return context
```

---

## ❓ FAQ

### Q: Where is data stored?
**A:** `~/.mcp-cookie-vault/` — encrypted `.json.enc` files. Master key in system keyring.

### Q: Can I use without encryption?
**A:** No, encryption is mandatory for security. Server won't start if keyring unavailable.

### Q: How to migrate profiles to another computer?
**A:**
1. Export profiles: `export_cookie_set(label, format="json")`
2. Copy files to new computer
3. Import: `import_cookie_set(label, filepath="...")`

⚠️ Master key doesn't migrate — re-import profiles.

### Q: Can I use with Puppeteer?
**A:** Yes, use `target="json"` in `load_cookies` and convert to Puppeteer format.

### Q: What if I forget profile name?
**A:** Use `list_cookie_sets()` to view all profiles or `search_profiles(tag="...")`.

### Q: How to clear everything?
**A:** Delete `~/.mcp-cookie-vault/` directory and key from keyring (via OS Credential Manager).

---

## 📄 License

MIT License

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Make changes
4. Run tests
5. Submit PR

---

## 📞 Support

- Issues: GitHub Issues
- Documentation: This README
