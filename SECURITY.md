# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of MCP Cookie Vault seriously. If you believe you've found a security vulnerability, please follow these steps:

### How to Report

1. **DO NOT** create a public GitHub issue
2. Email: [your-email@example.com] (replace with actual email)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Initial Response**: Within 48 hours
- **Status Update**: Within 5 business days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1 week
  - Medium: 2 weeks
  - Low: 4 weeks

### Security Best Practices

When using MCP Cookie Vault:

1. **Protect your master key**
   - It's stored in OS keyring — protect your OS user account
   - Use strong passwords on your computer

2. **Review audit logs regularly**
   - Check `~/.mcp-cookie-vault/audit.log`
   - Look for unexpected operations

3. **Use domain restrictions**
   - Configure `allowlist_domains` in config.yaml
   - Block sensitive domains (banking, etc.)

4. **Backup securely**
   - Export profiles with `export_cookie_set`
   - Store exports encrypted
   - Delete exports after import

5. **Keep software updated**
   - Update MCP Cookie Vault regularly
   - Keep Python and dependencies current

## Security Features

### Encryption

- **Algorithm**: Fernet (AES-128-CBC + HMAC-SHA256)
- **Key Storage**: OS keyring (Windows Credential Manager, macOS Keychain, Linux Secret Service)
- **Data at Rest**: All profile files encrypted

### Access Control

- **Domain Allowlist**: Restrict to specific domains
- **Domain Denylist**: Block specific domains
- **Confirmation Requirements**: For sensitive operations
- **Audit Logging**: All operations recorded

### Data Protection

- **Metadata by Default**: Cookie values hidden without confirmation
- **No Plaintext Storage**: All sensitive data encrypted
- **Secure Deletion**: Profile files deleted on removal

## Known Limitations

1. **Keyring Dependency**: Requires functioning OS keyring
2. **Single User**: Designed for single-user scenarios
3. **No HSM**: Master key in software keyring, not hardware

## Security Audit

This project has not undergone external security auditing. Use at your own risk in production environments.

## Responsible Disclosure

We follow a coordinated disclosure policy:

1. Reporter submits vulnerability
2. We verify and assess the issue
3. We develop and test a fix
4. Fix is released
5. Reporter is credited (with permission)

## Contact

For security-related questions: [your-email@example.com]
