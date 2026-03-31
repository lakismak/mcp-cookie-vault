# Changelog

All notable changes to MCP Cookie Vault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### Added
- Initial release
- Core functionality: save, load, delete, export, import cookies
- Encrypted storage with OS keyring integration
- Audit logging for all operations
- Domain allowlist/denylist filtering
- Confirmation requirements for sensitive operations
- Playwright, requests, and Netscape format support
- MCP resources for profile and audit log viewing
- Comprehensive test suite
- Developer documentation

### Security
- Fernet encryption for all stored data
- Master key stored in OS keyring (not on disk)
- Metadata-by-default (cookie values hidden)
- Explicit confirmation for sensitive operations
- Domain-based access control

## [1.0.0] - 2026-03-31

### Added
- Initial public release
