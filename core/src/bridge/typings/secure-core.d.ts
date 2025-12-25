/* ============================================================
   RCXCloud Secure Core – WASM Type Definitions
   API FREEZE v1.0
   ============================================================ */

/**
 * Stable error codes returned by Secure Core.
 * MUST match CoreError enum in Rust.
 */
export enum CoreError {
  Locked = 1,
  Killed = 2,
  InvalidInput = 3,
  CryptoFailure = 4,
  IntegrityFailure = 5,
  Denied = 6,
}

/**
 * Result wrapper used by all security-sensitive operations.
 */
export type CoreResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: CoreError };

/**
 * WASM-bound Secure Core handle.
 *
 * SECURITY NOTES:
 * - Thin wrapper over native core
 * - Kill-aware
 * - Fail-closed
 * - No guarantees of availability
 */
export class WasmCore {
  /**
   * Create a Secure Core instance.
   *
   * NOTE:
   * - Constructor NEVER throws
   * - All failures are deferred to method calls
   */
  constructor();

  /* ───────────── LIFECYCLE ───────────── */

  /**
   * Unlock Secure Core using recovery phrase (Strategy-A).
   *
   * SECURITY:
   * - Phrase is zeroized internally
   * - Forbidden after kill
   */
  unlock_with_phrase(
    phrase: Uint8Array
  ): CoreResult<void>;

  /**
   * Lock the keystore (local lock).
   *
   * NOTE:
   * - No effect after kill
   */
  lock(): void;

  /**
   * Apply irreversible remote kill.
   *
   * SECURITY:
   * - Fire-and-forget
   * - Process-lifetime irreversible
   * - All future calls will fail
   */
  apply_remote_kill(blob: Uint8Array): void;

  /**
   * Check whether Secure Core is killed.
   */
  is_killed(): boolean;

  /* ───────────── FILE CRYPTO ───────────── */

  /**
   * Encrypt a file chunk.
   *
   * SECURITY:
   * - Deterministic nonce
   * - Typed AAD
   * - Fail-closed
   */
  encrypt_chunk(
    file_id: bigint,
    cloud_id: number,
    chunk: number,
    plaintext: Uint8Array
  ): CoreResult<Uint8Array>;

  /**
   * Decrypt + authenticate a file chunk.
   *
   * SECURITY:
   * - Authenticated before plaintext exposure
   */
  decrypt_chunk(
    file_id: bigint,
    cloud_id: number,
    chunk: number,
    ciphertext: Uint8Array
  ): CoreResult<Uint8Array>;

  /* ───────────── STRATEGY-B RECOVERY ───────────── */

  /**
   * Export Strategy-B recovery blob.
   *
   * SECURITY:
   * - Capability-gated
   * - Opaque, versioned blob
   */
  export_recovery_blob(): CoreResult<Uint8Array>;

  /**
   * Import Strategy-B recovery blob.
   *
   * SECURITY:
   * - Replaces current session
   * - Integrity verified
   */
  import_recovery_blob(
    blob: Uint8Array,
    password: Uint8Array
  ): CoreResult<void>;

  /**
   * Permanently disable Strategy-B recovery.
   *
   * SECURITY:
   * - IRREVERSIBLE
   */
  disable_recovery(): CoreResult<void>;

  /**
   * Check if Strategy-B recovery is enabled.
   */
  is_recovery_enabled(): boolean;
}