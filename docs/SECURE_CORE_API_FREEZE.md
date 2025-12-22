# RCXCloud Secure Core — API Freeze (v1.0)

## STATUS: 🔒 FROZEN

This document defines the **frozen public API surface** of the RCXCloud Secure Core.
Any change to this surface **REQUIRES a formal security review**.

The Secure Core is a **trust anchor**.
Its APIs are intentionally small, explicit, and misuse-resistant.

---

## CORE PRINCIPLES (NON-NEGOTIABLE)

- Robust ≠ more code
- Fewer states, fewer footguns
- Fail closed, always
- No soft kill
- No key material outside Secure Core
- No crypto in UI / application layers
- Security over elegance

---

## TRUST BOUNDARY

The Secure Core owns **all** of the following:

- Cryptographic primitives
- Key derivation & hierarchy
- Memory locking & zeroization
- Session lifecycle
- Recovery semantics
- Kill semantics
- Policy enforcement (capabilities)

Everything outside the Secure Core is **untrusted**.

---

## FROZEN MODULES (PUBLIC SURFACE)

### 1. `core::bridge::api`

This is the **ONLY supported integration surface** for:
- UI layers
- JNI / FFI
- Plugins (WASM, Python, Swift, etc.)

No other module may be called from outside Secure Core.

#### Frozen Types

```rust
pub struct Core;
pub struct EncryptResult { pub total_len: usize }
pub struct VerifyResult(pub bool);

pub enum CoreError {
    Locked,
    Killed,
    InvalidInput,
    CryptoFailure,
}


### Frozen Operations 

```rust

impl Core {
    pub fn new() -> Self;

    pub fn unlock_with_phrase(
        &self,
        phrase: Vec<u8>,
    ) -> Result<(), CoreError>;

    pub fn encrypt_chunk(
        &self,
        file_id: u64,
        cloud_id: u16,
        chunk: u32,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<EncryptResult, CoreError>;

    pub fn decrypt_chunk(
        &self,
        file_id: u64,
        cloud_id: u16,
        chunk: u32,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<VerifyResult, CoreError>;

    pub fn lock(&self);

    pub fn apply_remote_kill(&self, kill_blob: &[u8]);

    pub fn is_killed(&self) -> bool;
}

No new functions may be added without review.



---

2. core::crypto

Internal only

Not callable by UI / plugins

APIs frozen internally

No raw primitives exposed



---

3. core::keystore

Internal authority

Exactly one active session

Unlock ONLY via RecoveryAuthority

Kill is irreversible



---

4. core::memory

Root of trusted dependency graph

Stack secrets forbidden

Locked heap only for long-lived keys

APIs frozen



---

RECOVERY STRATEGY GUARANTEE

v1.0 guarantees:

Strategy A (deterministic derived keys) — DEFAULT

Strategy B (random per-file keys + recovery blob) — SUPPORTED


Strategy selection is policy-controlled, not UI-controlled.


---

WHAT IS EXPLICITLY NOT PART OF v1.0

UI-driven key export

Arbitrary key access

Partial kill

Session cloning

Multi-session keystores

Soft recovery

Debug backdoors



---

CHANGE CONTROL

Any change to:

core::bridge::api

recovery semantics

kill semantics

memory guarantees


Requires:

1. Written security justification


2. Threat analysis


3. Explicit version bump




---

FINAL NOTE

This API is intentionally boring.

If an API feels “convenient”, it probably does not belong in Secure Core.

---

# 📐 UI CONTRACT DEFINITION

This defines **what the UI is allowed to do — and nothing more**.

---

## UI ROLE (STRICT)

The UI is a **requestor**, never an authority.

The UI:
- never holds keys
- never derives keys
- never chooses crypto primitives
- never enforces policy
- never bypasses Secure Core

---

## UI → SECURE CORE CONTRACT

### Allowed UI Actions

| UI Action | Secure Core Call |
|---------|------------------|
Unlock vault | `unlock_with_phrase()` |
Encrypt file chunk | `encrypt_chunk()` |
Decrypt file chunk | `decrypt_chunk()` |
User logout | `lock()` |
Remote kill received | `apply_remote_kill()` |
Status check | `is_killed()` |

---

## UI FAILURE MODEL (MANDATORY)

The UI MUST treat **all failures as non-recoverable by default**.

| Condition | UI Behavior |
|---------|-------------|
`CoreError::Killed` | Immediately lock UI, wipe UI state |
`CoreError::Locked` | Prompt for unlock |
Any crypto failure | Abort operation, retry later |
NULL / empty JNI return | Treat as fatal |

---

## UI MEMORY RULES

- UI buffers are **non-secret**
- UI must assume Secure Core wipes outputs on failure
- UI must never cache plaintext
- UI must zero buffers after use (best effort)

---

## UI STATE MACHINE (SIMPLIFIED)

START ↓ LOCKED ↓ unlock_with_phrase ACTIVE ↓ encrypt / decrypt ACTIVE ↓ lock LOCKED ↓ apply_remote_kill KILLED (TERMINAL)

No transitions exist **out of KILLED**.

---

## UI PROHIBITIONS (ENFORCED BY DESIGN)

UI MUST NOT:

- Retry after kill
- Attempt alternate crypto
- Cache session state
- Implement recovery logic
- Interpret ciphertext
- Modify AAD fields

---

## UI TEST REQUIREMENTS

UI integration tests MUST include:

- Kill during upload
- Kill during decrypt
- Unlock after kill (must fail)
- Chunk replay attempt (must fail)
- Version mismatch (must fail)

---

## FINAL UI RULE

> **If the UI thinks it can fix something, it’s wrong.**  
> Secure Core is the authority.

---

