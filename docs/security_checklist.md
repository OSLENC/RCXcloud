RCXCLOUD — SECURITY CHECKLIST (PER MODULE)
Secure Core (core/)
• [ ] AES-256-GCM only
• [ ] Argon2id for password KDF
• [ ] No plaintext keys in memory longer than session
• [ ] Zeroize on lock, background, kill
• [ ] No logging of secrets
• [ ] Integrity checked before decrypt
Application Logic (application/)
• [ ] Integrity verified after every download
• [ ] RetryQueue has cap + backoff
• [ ] StatusMatrix marks degraded clouds
• [ ] RoutingPolicy enforces user rules
JNI / Bridge
• [ ] No raw keys cross JNI
• [ ] No decrypted buffers to UI
• [ ] Passwords passed once, wiped immediately
Android UI
• [ ] FLAG_SECURE enabled
• [ ] Auto-lock on background
• [ ] No screenshots
• [ ] Root warning shown if detected
• [ ] Session state reflected visually
Cloud Drivers
• [ ] Encrypted blobs only
• [ ] No retry loops inside driver
• [ ] Structured error reporting
• [ ] No plaintext filenames
Transport
• [ ] TLS everywhere
• [ ] SSH preferred for NAS
• [ ] Bluetooth/USB pairing only
• [ ] No open HTTP endpoints
Recovery
• [ ] Encrypted recovery file
• [ ] Split recovery supported
• [ ] Keys never auto-restored without auth
CI / Testing
• [ ] Fuzz crypto, JNI, parsers
• [ ] Simulate corruption
• [ ] Simulate cloud failure
• [ ] Size regression checks