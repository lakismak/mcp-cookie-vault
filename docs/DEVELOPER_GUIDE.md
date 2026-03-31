# Developer Guide

## Architecture Overview

MCP Cookie Vault consists of four main components:

### 1. Models (`models.py`)
- `Cookie` — Single cookie representation
- `SessionProfile` — Container for cookies + browser state
- `AuditEntry` — Audit log entry

### 2. Storage (`storage.py`)
- `EncryptedStorage` — Fernet-encrypted file storage
- `AuditLog` — Plain text operation logging

### 3. Configuration (`config.py`)
- `SecurityConfig` — Domain filtering, limits, confirmations

### 4. Server (`server.py`)
- MCP tools and resources
- FastMCP server definition

## Security Model

```
User Request
    ↓
MCP Server (server.py)
    ↓
SecurityConfig (config.py) ← Check domain, limits, confirm
    ↓
EncryptedStorage (storage.py) ← Decrypt with key from OS Keyring
    ↓
SessionProfile (models.py)
```

## Key Security Features

1. **Master Key in OS Keyring**
   - Windows: Credential Manager
   - macOS: Keychain
   - Linux: Secret Service (GNOME Keyring / KWallet)

2. **Fernet Encryption**
   - Symmetric encryption (AES-128-CBC + HMAC-SHA256)
   - Key rotated only on vault recreation

3. **Metadata by Default**
   - `get_metadata()` returns info without cookie values
   - Values only revealed with explicit `confirm=true`

4. **Audit Logging**
   - All operations logged
   - Tamper-evident (append-only)

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=mcp_cookie_vault

# Lint
ruff check mcp_cookie_vault tests
black --check mcp_cookie_vault tests
```

## Code Style

- **Line length**: 100 characters
- **Type hints**: Required for all public APIs
- **Docstrings**: Google style for public methods
- **Async**: Use `async/await` for I/O operations

## Adding New Tools

1. Define tool with `@mcp.tool()` decorator
2. Add input validation
3. Check security config (domain, confirmations)
4. Log operation to audit log
5. Return clear status messages

Example:
```python
@mcp.tool()
async def my_new_tool(param: str, confirm: bool = False) -> str:
    """Tool description."""
    config = get_config()

    # Security checks
    if config.require_confirm_for_reveal and not confirm:
        return "❌ Confirmation required"

    # Operation
    storage = get_storage()
    # ... do something ...

    # Log
    if config.audit_logging:
        await get_audit_log().log("my_action", param)

    return "✅ Success"
```

## Release Checklist

- [ ] Update version in `pyproject.toml`
- [ ] Update version in `__init__.py`
- [ ] Update CHANGELOG.md
- [ ] Run all tests
- [ ] Check ruff/black linting
- [ ] Update README if API changed
- [ ] Build package: `python -m build`
- [ ] Test installation from dist/
- [ ] Tag release: `git tag -a v1.0.0 -m "Release 1.0.0"`
- [ ] Push tag: `git push origin v1.0.0`
- [ ] Publish to PyPI: `twine upload dist/*`

## Troubleshooting

### Keyring Issues

If keyring is not available:
```python
# Check keyring status
import keyring
print(keyring.get_keyring())
```

### Encryption Errors

If decryption fails:
1. Check keyring has `mcp-cookie-vault:master_key`
2. Verify vault files exist: `~/.mcp-cookie-vault/*.json.enc`
3. Check file permissions

### Audit Log Corruption

If audit.log is corrupted:
```bash
# Safe to delete (will recreate)
rm ~/.mcp-cookie-vault/audit.log
```
