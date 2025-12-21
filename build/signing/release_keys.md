# Release Signing Keys (DOCUMENTATION ONLY)

⚠️ **SECURITY WARNING**

This file **must never contain real cryptographic keys**.

## Rules

- ❌ No private keys
- ❌ No public keys
- ❌ No certificates
- ❌ No key IDs linked to real systems
- ❌ No secrets, tokens, or credentials of any kind

This document exists **only to describe the signing process**, not to store secrets.

---

## Correct Key Handling Policy

All real signing keys **must** be:

- Generated **offline**
- Stored in:
  - Hardware Security Modules (HSM), or
  - Air-gapped devices, or
  - Secure secret managers (never Git)
- Injected into CI/CD **at runtime** using:
  - Encrypted environment variables
  - Secure key vaults
  - Manual release ceremonies

---

## CI/CD Expectations

- CI pipelines **must fail** if:
  - A key-like pattern is detected
  - This file is modified to include secrets
- Automated scanners (e.g. trufflehog, gitleaks) **must remain enabled**

---

## Enforcement

Any pull request that:
- Adds real keys
- Adds key material
- Adds encoded secrets (base64, hex, PEM, etc.)

will be **rejected immediately**.

---

## Summary

> 🔐 **Keys live outside Git. Always. No exceptions.**

This file is documentation only.
