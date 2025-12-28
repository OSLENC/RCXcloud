# RCXCloud Termux Bootstrap Guide

This document records the **canonical, battle-tested process**
for building RCXCloud Secure Core + Android JNI apps inside Termux.

---

## ✅ Supported Environment

| Component | Version |
|---------|--------|
| Termux | latest |
| Android SDK | API 34 |
| NDK | 25.1.8937393 |
| Java | 17 |
| Rust | distro package |
| Gradle | wrapper (8.2) |

---

## ❌ What NOT To Do (Critical)

### 1. Do NOT use Linux x86 Android NDK
Symptoms:
clang: cannot execute binary file: Exec format error

Cause:
- x86_64 binaries on ARM device

Fix:
- Use `pkg install android-sdk`
- Never unzip NDK manually

---

### 2. Do NOT let Gradle download aapt2
Symptoms:
aapt2: Syntax error: Unterminated quoted string

Cause:
- Gradle downloads x86 aapt2

Fix:
```properties
android.aapt2FromMavenOverride=$PREFIX/bin/aapt2

3. Do NOT hardcode clang paths
Bad:

export CC=$ANDROID_NDK_HOME/.../linux-x86_64/clang

Correct:

Let Cargo use Termux clang

Use .cargo/config.toml only

4. Do NOT use Java 21

Symptoms:

D8 crashes
Gradle toolchain mismatch
Use:
OpenJDK 17 only

✅ What Is Safe
✔ Termux clang
✔ Termux aapt2
✔ Android SDK from Termux repo
✔ JNI inside Secure Core (feature-gated)
✔ llvm-nm -D for symbol audits

##🔐 RCXCloud-Specific Rules
Secure Core owns JNI
feature = "android" must be explicit
No cloud SDKs in core
No NDK auto-detection via Gradle
##JNI symbols audited via:

llvm-nm -D librcxcore.so | grep Java_

##🧪 Verified JNI Exports

Java_com_rcxcloud_core_SecureCore_unlockWithPhrase
Java_com_rcxcloud_core_SecureCore_lock
Java_com_rcxcloud_core_SecureCore_isKilled
Java_com_rcxcloud_core_SecureCore_encryptChunk
Java_com_rcxcloud_core_SecureCore_decryptChunk

##📌 Final Notes
Bootstrap scripts are idempotent
All failures encountered are documented here
This guide is authoritative unless superseded by a security review



