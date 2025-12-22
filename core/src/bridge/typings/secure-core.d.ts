/* ============================================================
   RCXCloud Secure Core – WASM Type Definitions
   API FREEZE v1.0
   ============================================================ */

export class WasmCore {
  constructor();

  /* ───────────── LIFECYCLE ───────────── */

  /**
   * Unlock Secure Core using recovery phrase (Strategy-A).
   * @param phrase Uint8Array containing phrase bytes
   * @returns true on success, false otherwise
   */
  unlock_with_phrase(phrase: Uint8Array): boolean;

  /**
   * Lock the keystore (local lock).
   */
  lock(): void;

  /**
   * Apply irreversible remote kill.
   * @param blob kill authorization blob
   */
  apply_remote_kill(blob: Uint8Array): void;

  /**
   * Check if Secure Core is killed.
   */
  is_killed(): boolean;

  /* ───────────── FILE CRYPTO ───────────── */

  /**
   * Encrypt a file chunk.
   *
   * @param file_id Stable file identifier
   * @param cloud_id Cloud identifier
   * @param chunk Chunk index
   * @param plaintext Raw chunk bytes
   * @returns Ciphertext or null on failure
   */
  encrypt_chunk(
    file_id: bigint,
    cloud_id: number,
    chunk: number,
    plaintext: Uint8Array
  ): Uint8Array | null;

  /**
   * Decrypt a file chunk.
   *
   * @param file_id Stable file identifier
   * @param cloud_id Cloud identifier
   * @param chunk Chunk index
   * @param ciphertext Encrypted chunk
   * @returns Plaintext or null on auth failure
   */
  decrypt_chunk(
    file_id: bigint,
    cloud_id: number,
    chunk: number,
    ciphertext: Uint8Array
  ): Uint8Array | null;

  /* ───────────── STRATEGY-B RECOVERY ───────────── */

  /**
   * Export Strategy-B recovery blob.
   * @returns Recovery blob or null
   */
  export_recovery_blob(): Uint8Array | null;

  /**
   * Import Strategy-B recovery blob.
   *
   * @param blob Recovery blob
   * @param password User password bytes
   * @returns true on success
   */
  import_recovery_blob(
    blob: Uint8Array,
    password: Uint8Array
  ): boolean;

  /**
   * Disable Strategy-B recovery permanently.
   */
  disable_recovery(): boolean;

  /**
   * Check if Strategy-B recovery is enabled.
   */
  is_recovery_enabled(): boolean;
}