# RCXCLOUD — Security Checklist (Per Module)

This document outlines the security requirements and implementation status for the RCXCloud architecture. Every pull request involving these modules must be verified against this checklist.

---

## 🔐 Secure Core (`core/`)
- [ ] **AES-256-GCM only**: Standardize on authenticated encryption.
- [ ] **Argon2id**: Use for all password-based Key Derivation Functions (KDF).
- [ ] **Memory Management**: No plaintext keys held in memory longer than the active session.
- [ ] **Lifecycle Clearing**: Zeroize/wipe sensitive data on app lock, background, or process kill.
- [ ] **Zero Logging**: Ensure no secrets, keys, or IVs are ever written to logs.
- [ ] **Integrity Checks**: Verify payload integrity before attempting decryption.

## ⚙️ Application Logic (`application/`)
- [ ] **Download Verification**: Post-download integrity verification for all assets/blobs.
- [ ] **RetryQueue**: Implement a maximum retry cap with exponential backoff.
- [ ] **StatusMatrix**: System accurately marks and handles degraded or offline cloud providers.
- [ ] **RoutingPolicy**: Strict enforcement of user-defined data routing rules.

## 🌉 JNI / Bridge
- [ ] **No Raw Keys**: Raw cryptographic keys must never cross the JNI boundary.
- [ ] **UI Safety**: Do not pass decrypted buffers directly to the UI layer.
- [ ] **Sensitive Handoff**: Passwords passed once; wiped from bridge memory immediately after use.

## 📱 Android UI
- [ ] **FLAG_SECURE**: Enabled to prevent screen recording and window sharing.
- [ ] **Auto-Lock**: Trigger security lock immediately when the app enters the background.
- [ ] **Anti-Screenshot**: Block system-level screenshots.
- [ ] **Environment Integrity**: Display a prominent warning if Root/Jailbreak is detected.
- [ ] **Visual State**: Current session security state must be reflected in the UI.

## ☁️ Cloud Drivers
- [ ] **Blob-Only Storage**: Ensure only encrypted blobs are uploaded to providers.
- [ ] **No Driver Loops**: Retry logic must be handled by `application/`, not inside the driver.
- [ ] **Standardized Errors**: Use structured error reporting for cloud-specific failures.
- [ ] **Metadata Privacy**: No plaintext filenames or sensitive metadata in cloud storage.

## 📡 Transport
- [ ] **End-to-End TLS**: Force TLS for all network communications.
- [ ] **NAS Security**: Prefer SSH/SFTP over SMB for Network Attached Storage.
- [ ] **Peripheral Security**: Bluetooth and USB connectivity require manual pairing only.
- [ ] **No Insecure Endpoints**: Zero open HTTP (non-HTTPS) endpoints permitted.

## 🛠️ Recovery
- [ ] **Encrypted Backups**: Recovery files must be encrypted with a separate key/passphrase.
- [ ] **Split Recovery**: Support for M-of-N split recovery mechanisms.
- [ ] **Auth-Gated Restore**: Keys must never be auto-restored without explicit user authentication.

## 🧪 CI / Testing
- [ ] **Fuzzing**: Automated fuzz testing for crypto implementation, JNI bridges, and parsers.
- [ ] **Fault Injection**: Simulate data corruption to test recovery logic.
- [ ] **Resilience Testing**: Simulate cloud provider failures and outages.
- [ ] **Binary Audits**: Check for size regressions and unintended symbol exports.
