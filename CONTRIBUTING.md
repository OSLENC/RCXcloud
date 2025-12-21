RCXCLOUD — CONTRIBUTOR GUIDE

Thank you for contributing to RCXCloud.
This project is security-critical, layered, and intentionally strict.
Please read this document fully before making changes.


---

1. CORE PRINCIPLES

RCXCloud is built on these non-negotiable rules:

🔐 No plaintext secrets outside core/

🧱 Strict layer boundaries

🧼 Clean workspace hygiene

🚫 No build artifacts in Git

🧪 Security invariants must be testable

🔄 Failures must be explicit, never silent


If a change violates any of the above, it will be rejected.


---

2. WORKSPACE STRUCTURE (CRITICAL)

RCXCloud is a single Cargo workspace with multiple crates.

Workspace root

RCXcloud/
├── Cargo.toml        ← THE ONLY workspace root
├── Cargo.lock        ← SINGLE shared lockfile
├── core/
├── application/
├── transport/
├── infrastructure/

Workspace members

core → Secure Core (trust anchor)

application → orchestration logic

transport → network & pairing

infrastructure → cloud drivers



---

3. WORKSPACE RULES (MANDATORY)

✅ Allowed

Each crate has its own Cargo.toml

All crates are listed in root Cargo.toml

One shared Cargo.lock at repo root

cargo build / cargo check run from repo root


❌ Forbidden

❌ Multiple workspace roots

❌ Nested workspaces

❌ Per-crate Cargo.lock

❌ Running cargo build inside sub-crates for commits

❌ Editing .gitignore to allow build artifacts


If you see an error like:

multiple workspace roots found

you have violated workspace rules.


---

4. BUILD ARTIFACT POLICY

NEVER commit:

target/
**/target/

Why this matters

Leaks build metadata

Breaks reproducibility

Pollutes diffs

Violates security hygiene


If target/ appears:

1. Delete it


2. Ensure .gitignore contains:

/target/
**/target/




---

5. LAYER OWNERSHIP RULES

core/ (SECURE CORE)

Owns:

Cryptography

Key material

Zeroization

Integrity checks

Encrypted logging

Media decoding

Policy enforcement


Must NOT:

Perform networking

Access cloud drivers

Access UI

Log plaintext secrets



---

application/

Owns:

Workflow orchestration

Retry logic

Routing decisions

Session state (NOT keys)


Must NOT:

Encrypt/decrypt

Hash

Store secrets

Implement crypto primitives


Application code emits events, it does not secure them.


---

transport/

Owns:

TLS

SSH tunnels

Bluetooth pairing

USB pairing

Local discovery


Must NOT:

See plaintext user data

See keys

Retry silently



---

infrastructure/

Owns:

Cloud transport

Upload/download mechanics

Provider abstraction


Must NOT:

Encrypt

Decrypt

Hash

Interpret data contents


Drivers only move opaque encrypted blobs.


---

6. JNI / FFI RULES

JNI is zero-trust.

❌ No raw keys cross JNI

❌ No decrypted buffers cross JNI

✅ Inputs validated at boundary

✅ Outputs sanitized

✅ Invariants must be enforced in code, not comments


If JNI changes are made:

Add boundary tests

Update fuzz coverage if applicable



---

7. EMPTY FILE POLICY

Empty files are allowed only when they serve one of these purposes:

mod.rs scaffolding

.keep placeholders

Explicit future extension points


All empty files must:

Be intentional

Be linted

Not contain dead or misleading paths



---

8. PLUGINS POLICY

The plugins/ directory is:

🚫 Disabled by default

🔒 Signed only

🧪 Sandboxed

⚠️ Optional


The presence of plugins/DISABLED_BY_DEFAULT is mandatory.

Do NOT enable plugins without:

Explicit documentation

Security review

Maintainer approval



---

9. CI & QUALITY GATES

All contributions must pass:

cargo check

cargo test

cargo metadata

Security linting

Fuzzing (where applicable)


Future CI may enforce:

deny(warnings)

clippy --deny

Zeroization tests

Invariant enforcement tests



---

10. WHEN IN DOUBT

If you are unsure:

Do not guess

Do not bypass

Ask or document assumptions


Security > convenience.


---

11. FINAL RULE

If a contribution makes RCXCloud:

Less secure

Less auditable

Less deterministic


It will not be merged.


---

Thank you for helping keep RCXCloud secure and correct.
