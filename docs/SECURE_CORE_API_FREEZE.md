
🔒 RCXCloud Secure Core — API FREEZE (v1.0)

Scope

core/memory

core/crypto

core/keystore

core/integrity


Audience

Core developers

Security auditors

Future maintainers

External reviewers



---

0️⃣ FOUNDATIONAL PRINCIPLE (NON-NEGOTIABLE)

> Secure Core exists to make insecure behavior impossible by construction.



Any API change that:

exposes raw secrets

allows alternate crypto paths

weakens kill semantics

introduces optional security


BREAKS THE CORE and INVALIDATES AUDITS


---

1️⃣ MEMORY API FREEZE

🔐 GuardedBox<T> / GuardedKey32

MUST NEVER

Implement Clone, Copy, Debug

Expose raw pointer

Allow stack-backed secrets

Skip mlock / VirtualLock

Allow allocation without zeroization on drop


ALLOWED

Borrowing via borrow() / borrow_mut()

Drop-based zeroization only


📌 Invariant

> A key must never exist outside locked heap memory.




---

🔐 Secret<T>

MUST NEVER

Provide into_inner

Implement Clone, Copy, Debug

Accept stack arrays like [u8; N]


ALLOWED

Heap-only construction

Scoped borrowing


📌 Invariant

> Ownership of secrets must never escape compile-time control.




---

2️⃣ CRYPTO API FREEZE

❌ FORBIDDEN FOREVER

encrypt(data, key)

decrypt(data, key)

Caller-supplied nonces

RNG-based nonces

Untyped aad: &[u8]

Returning plaintext on auth failure

Partial decryption output



---

✅ REQUIRED CRYPTO SHAPE

AEAD ONLY

AES-GCM or equivalent

Authenticated encryption mandatory


Deterministic Nonces

Derived internally

Based on (file_id, chunk)

No counters

No RNG


Typed AAD

struct Aad {
    file_id: u64,
    chunk: u32,
    cloud_id: u16,
    version: u8,
}

📌 Invariant

> If AAD changes, decryption must fail.




---

🔑 Key Derivation (derive.rs)

MUST

Use HKDF

Use purpose tags

Be deterministic

Never panic

Return GuardedKey32


MUST NEVER

Reuse Purpose values

Reorder Purpose enum

Allow raw key bytes to escape


📌 Invariant

> Master key must NEVER encrypt data directly.




---

3️⃣ KEYSTORE API FREEZE

🔥 Kill Semantics (ABSOLUTE)

GLOBAL_KILLED

Process-lifetime irreversible

Cannot be reset

Must be checked on every operation


MUST NEVER

Allow unlock after kill

Allow session reuse

Allow key recovery post-kill


📌 Invariant

> Kill means cryptographic death, not logout.




---

🔐 MasterKeyStore

MUST

Accept ownership of GuardedKey32

Fail closed on mutex poisoning

Provide handle-based access only


MUST NEVER

Return raw keys

Implement Debug for secrets

Cache derived keys globally



---

🔐 Session

MUST

Be !Send / !Sync

Zeroize key on drop or kill

Use deterministic nonce

Require typed AAD

Fail on global kill


MUST NEVER

Store nonce counters

Expose session keys

Survive kill signal



---

4️⃣ INTEGRITY API FREEZE

Hashing

Hash outputs may be logged

Inputs must never be secrets unless wrapped


Verification

Must be constant-time

Must fail closed

Must not panic


📌 Invariant

> Integrity failures are authentication failures.




---

5️⃣ ERROR HANDLING RULES (CRITICAL)

PANIC POLICY

Panic = abort

Abort = security failure

Panic is acceptable only when continuing is unsafe


ERROR POLICY

Errors must be explicit

No silent fallback

No recovery after crypto failure



---

6️⃣ TESTING & TOOLING FREEZE

REQUIRED TESTS

Decrypt fuzz tests

Tampered AAD rejection

Nonce reuse detection

Kill-after-unlock behavior

Poisoned mutex handling


FORBIDDEN

Snapshot tests with secrets

Logging raw buffers

Mock crypto in Secure Core



---

7️⃣ DOCUMENTATION FREEZE

Every Secure Core module MUST document:

Trust level

Formal invariants

What MUST NOT be changed

Kill semantics



---

8️⃣ VERSIONING RULE

Any change to Secure Core requires:

1. Security review


2. Version bump


3. Changelog entry


4. Re-audit



📌 Invariant

> Secure Core is not “iterated”, it is re-certified.




---

✅ FINAL FREEZE STATUS

Module	Freeze Status

memory	🔒 Frozen
crypto	🔒 Frozen
keystore	🔒 Frozen
integrity	🔒 Frozen


RCXCloud Secure Core v1.0 is READY.


---
