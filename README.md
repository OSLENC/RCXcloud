# RCXCLOUD — SYSTEM ARCHITECTURE

RCXCloud is a **security-first, privacy-preserving, multi-cloud storage and media system** designed with strong cryptographic guarantees, strict layering, and long-term extensibility.

This repository contains the **authoritative architecture and implementation skeleton**.

---

## 1. SYSTEM GOALS

RCXCloud is a:

- Secure, privacy-first multi-cloud storage system
- NAS-like abstraction over **untrusted** cloud providers
- Media-capable (gallery, video, subtitles, HDR)
- Android-first, Rust-anchored
- Future-proof (post-quantum ready)

---

## 2. NON-NEGOTIABLE PRINCIPLES

- No plaintext data at rest
- No secrets outside the Secure Core
- UI never performs cryptography
- Cloud providers are untrusted
- Failures are visible, never silent
- Integrity is enforced, not optional
- Session ≠ pairing
- Post-quantum crypto must be pluggable without redesign

---

## 3. STACKING ARCHITECTURE

### Layers (Top → Bottom)

1. Presentation Layer (Android UI / TUI)
2. Application Logic Layer
3. Session & Identity Layer
4. Secure Core (Rust Trust Anchor)
5. Bridge Layer (JNI / Protobuf)
6. Transport Layer (TLS / SSH / Bluetooth / USB)
7. Infrastructure Layer (Cloud Drivers)
8. OS / Hardware

### Access Rules

**Allowed**
- Each layer may only call the layer directly below it

**Forbidden**
- UI → Secure Core  
- UI → Cloud Drivers  
- Cloud Drivers → Secure Core  
- JNI → Key material  

---

## 4. LAYER RESPONSIBILITIES

### 4.1 Presentation Layer (Android UI / TUI)

**Responsibilities**
- Display state
- Collect user input
- Trigger actions via ViewModels

**Must NOT**
- Store secrets
- Perform cryptography
- Call cloud drivers directly

**Technology**
- Kotlin
- Jetpack Compose
- Material 3

---

### 4.2 Application Logic Layer

**Responsibilities**
- Orchestrate workflows
- Apply routing rules
- Manage retries
- Enforce integrity checks

**Key Module**
- `application/cloud_manager.rs`

---

### 4.3 Session & Identity Layer

**Responsibilities**
- Master password verification
- Biometric unlock (session only)
- Session timeout & auto-lock
- Device registry
- Remote kill

---

### 4.4 Secure Core (Rust Trust Anchor)

**Responsibilities**
- AES-256-GCM encryption
- Argon2id KDF
- Key lifecycle management
- Memory zeroization
- Integrity hashing
- Media decoding
- Policy enforcement

**Rules**
- No network access
- No UI access
- No logging of secrets

---

### 4.5 Bridge Layer (JNI / Protobuf)

**Responsibilities**
- Controlled data marshaling
- No key exposure

---

### 4.6 Transport Layer

**Channels**
- HTTPS (TLS)
- SSH tunnels (preferred for NAS)
- Bluetooth (pairing only)
- USB (pairing only)

---

### 4.7 Infrastructure Layer (Cloud Drivers)

**Supported**
- rclone (generic)
- Native S3
- Native Google Drive SDK

**Rules**
- Drivers never see plaintext
- Drivers never retry silently
- Drivers return structured errors

---

## 5. MEDIA PIPELINE

Implemented inside the Secure Core (Rust):

- Image decode (JPEG / PNG / WEBP)
- Video decode (H.264 / H.265 / VP9 / AV1)
- Audio decode (AAC / MP3 / Opus / FLAC)
- Multi-audio track support
- Subtitle decode (SRT / VTT / ASS)
- HDR detection
- Dolby passthrough
- EXIF / metadata stripping
- No plaintext on disk

---

## 6. PERFORMANCE STRATEGY

- Parallel upload / download
- Chunked streaming
- Adaptive retry with backoff
- Zero-copy buffers where possible
- Hardware codecs preferred
- Adaptive bitrate playback

---

## 7. POST-QUANTUM SLOT (RESERVED)

- Define KEM interface only
- No post-quantum implementation yet
- Must be swappable without redesign

---

## 8. INTENTIONALLY DEFERRED

These do **not** block the secure MVP:

- Advanced UI animations
- Custom themes
- Plugin marketplace
- Post-quantum algorithm swap-in
- AI features

---

## 9. FINAL RULES

- Secrets → Secure Core only
- UX → UI only
- Network → Drivers only
- No silent failures
- Integrity is mandatory

---

## 10. SECURITY CHECKLIST

See: [`docs/security_checklist.md`](docs/security_checklist.md)

This checklist is **mandatory** for all contributions and reviews.

---

## LICENSE

Apache License 2.0  
Automated analysis, security review, and AI-based inspection are explicitly permitted.
