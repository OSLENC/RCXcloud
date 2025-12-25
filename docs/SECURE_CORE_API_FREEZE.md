---

RCXCloud Secure Core — API Freeze (v1.0)


---

1. Purpose of This Document

This document freezes the public API surface of the RCXCloud Secure Core for version 1.0.

> Freeze means:
Any change to the items listed here is a breaking security change and requires:

explicit version increment

security review

migration plan

audit update




This applies to Rust APIs, JNI interfaces, and UI-visible contracts.


---

2. Core Security Philosophy (Frozen)

These principles MUST NEVER CHANGE without a major version bump:

Robust ≠ more code

Fewer states → fewer vulnerabilities

Misuse-resistant APIs over convenience

Determinism over randomness where possible

Fail-closed always

No soft kill, no partial kill, no recovery after kill

Admin is a capability superset, never a bypass

UI and JNI are untrusted shells



---

3. Global Kill Semantics (Frozen)

3.1 Kill Properties

Kill is cryptographically verified

Kill is process-lifetime irreversible

Kill zeroizes all secret material

After kill:

No unlock

No encryption

No decryption

No recovery

No JNI output except failure



3.2 Kill Enforcement Order

1. Notify execution start


2. Invalidate device identity


3. Wipe keystore & sessions


4. Execute final kill


5. Never return control




---

4. Memory Model (Frozen)

4.1 Guarded Memory

All long-lived secrets:

Heap-only

Page-locked (mlock / VirtualLock)

Zeroized on drop


Types:

GuardedBox<T>

GuardedKey32



4.2 Secret Ownership

No stack-resident secrets

No Clone, Copy, or Debug

Deterministic zeroization

No raw key byte exposure


4.3 Zeroization Guarantees

Explicit wipe APIs

Drop-based zeroization

Panic-safe initialization



---

5. Keystore & Session Model (Frozen)

5.1 Keystore Invariants

Single authority

Exactly one active session

Mutex poisoning → permanent kill

Unlock impossible after kill

Session keys never escape guarded memory


5.2 Session Invariants

Operation-based session

Deterministic nonce derivation

Typed AAD mandatory

Session is killable and irreversible

!Send / !Sync by construction


5.3 Recovery Authority

Recovery produces authority, not keys

Single-use

Heap-only

Integrity verified before session creation



---

6. Cryptography API (Frozen)

6.1 Algorithms (Fixed)

AEAD: AES-256-GCM

KDF: HKDF-SHA256

Password KDF: Argon2id

Nonce derivation: HMAC-SHA256

Hashing: SHA-256


6.2 Deterministic Design

No RNG in file encryption

Nonces derived from:

key

file_id

chunk index


AAD is structured and authenticated


6.3 Prohibited

Raw encrypt/decrypt APIs

Caller-supplied nonces

Unauthenticated plaintext output

Panic-based crypto logic



---

7. File Encryption Pipeline (Frozen)

7.1 Chunk Model

Explicit chunk boundaries

Maximum chunk size enforced

Versioned crypto format


7.2 AAD Structure (Frozen)

Fields (fixed width):

file_id (u64)

chunk (u32)

cloud_id (u16)

version (u8, non-zero)


Serialization is deterministic and fail-closed.


---

8. Encryption Strategies (Frozen)

Strategy A — Default

Deterministic Derived Keys

Keys derived from session root + file_id

Fast

No external recovery files

Recommended default


Strategy B — Advanced (Opt-In)

Random Per-File Keys

Cryptographically random keys per file

No derivation pattern reuse

Keys encrypted under recovery root

Optional recovery export


Strategy-B Guarantees

Cloud compromise ≠ key compromise

File-to-file isolation

Explicit user consent required


Strategy-C

❌ Explicitly rejected for v1.0
(Complexity > security gain)


---

9. Strategy-B Recovery (Frozen)

9.1 Recovery Blob

Encrypted

Authenticated

Versioned

Opaque to UI/JNI

No raw keys exposed


9.2 Operations

Export recovery blob

Import recovery blob

Permanently disable recovery


9.3 Irreversibility

Disable recovery = permanent

Cannot be re-enabled

Cannot be bypassed by admin



---

10. Policy & Capability System (Frozen)

10.1 Capability Rules

Capabilities are permissions, not roles

Additive only

Evaluated only in Secure Core

UI cannot override


10.2 Key Capabilities

Encrypt / Decrypt

Upload / Download

UseStrategyB

ExportRecovery

ImportRecovery

DisableRecovery

IssueKill / ExecuteKill



---

11. JNI Bridge Contract (Frozen)

11.1 JNI Rules

Thin adapter only

No crypto

No policy logic

No secret storage

Panic-safe

Fail-closed


11.2 JNI Responsibilities

Marshal inputs/outputs

Enforce size checks

Convert errors to codes

Return NULL/0 on failure


11.3 Strategy-B JNI APIs (Frozen)

exportStrategyBRecovery() -> byte[]

importStrategyBRecovery(byte[]) -> int

disableStrategyBRecovery() -> int



---

12. UI Contract (Frozen)

12.1 UI Is Untrusted

UI never handles keys

UI never sees plaintext crypto material

UI never decides policy


12.2 UI Responsibilities

Capability-aware presentation

Explicit user consent for:

Strategy-B

Recovery export/import

Kill actions


Clear irreversible warnings


12.3 UI Must Assume

Core can fail at any time

Kill may happen asynchronously

Operations may become unavailable permanently



---

13. Media Pipeline (Frozen)

13.1 Secure Core Scope

Demux, decode, sanitize

Encrypted input → decoded frames/audio only

No rendering in core


13.2 Invariants

No metadata leakage

Size and format limits enforced

Kill-aware at every stage

Fuzz-tested decode paths



---

14. Testing & Audit Requirements (Frozen)

14.1 Mandatory Tests

Fuzzing:

decrypt paths

demux/decoder

malformed recovery blobs


Property tests:

nonce uniqueness

AAD binding

kill irreversibility



14.2 CI Rules

Any panic = failure

Any unwrap in Secure Core = failure

Coverage required on crypto + keystore paths



---

15. What MUST NEVER Change in v1.x

❌ Kill semantics
❌ Memory model
❌ Key derivation rules
❌ AAD layout
❌ Deterministic nonce design
❌ Capability enforcement location
❌ Strategy-A default behavior


---

16. Versioning Policy

v1.x: bug fixes only (no semantic change)

v2.0: any cryptographic or lifecycle change

Every major bump requires:

New freeze document

Migration plan

Full audit




---

17. Final Statement

> This Secure Core is intentionally restrictive.
Any perceived inconvenience is a deliberate security boundary.






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

## TypeScript / WASM Contract

The Secure Core exposes a language-agnostic WASM interface.

The canonical TypeScript definition file (`secure-core.d.ts`) is:
- Normative
- Frozen for v1.0
- Must match `core/src/bridge/api.rs` exactly

Breaking changes to:
- method names
- argument order
- return types
- failure semantics

are **FORBIDDEN** without a major version bump.

All UI, plugin, and third-party code MUST consume Secure Core
through this contract.

---
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

Frozen Operations

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

