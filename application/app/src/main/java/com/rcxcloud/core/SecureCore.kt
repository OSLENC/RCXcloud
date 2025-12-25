package com.rcxcloud.core

object SecureCore {
    init {
        try {
            System.loadLibrary("rcxcore")
        } catch (e: UnsatisfiedLinkError) {
            e.printStackTrace()
        }
    }

    external fun unlockWithPhrase(phrase: ByteArray): Int
    external fun lock()
    external fun isKilled(): Int
    external fun encryptChunk(fileId: Long, cloudId: Int, chunk: Int, plaintext: ByteArray): ByteArray?
    external fun decryptChunk(fileId: Long, cloudId: Int, chunk: Int, ciphertext: ByteArray): ByteArray?
}
