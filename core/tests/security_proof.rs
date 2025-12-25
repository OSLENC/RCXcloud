use rcxcore::bridge::api::Core;

#[test]
fn prove_secure_core_lifecycle() {
    // 1. BOOTSTRAP: Initialize the Core (simulating App Launch)
    let core = Core::new();
    println!("✅ [SECURE CORE] Initialized.");

    // 2. AUTHENTICATION: Simulating user entering a passphrase
    // For this test, we mimic a 32-byte recovery phrase/hash
    let dummy_phrase = vec![1u8; 32]; 
    
    match core.unlock_with_phrase(dummy_phrase) {
        Ok(_) => println!("✅ [KEYSTORE] Unlocked successfully."),
        Err(e) => panic!("❌ [KEYSTORE] Failed to unlock: {:?}", e),
    }

    // 3. ENCRYPTION: Simulate uploading a file chunk
    let file_id = 101010;
    let cloud_id = 1;
    let chunk_index = 0;
    let plaintext = b"This is a top secret cloud document.";
    let mut ciphertext_buffer = vec![0u8; plaintext.len() + 16]; // +16 for Tag

    match core.encrypt_chunk(
        file_id, 
        cloud_id, 
        chunk_index, 
        plaintext, 
        &mut ciphertext_buffer
    ) {
        Ok(res) => println!("✅ [CRYPTO] Encrypted {} bytes.", res.total_len),
        Err(e) => panic!("❌ [CRYPTO] Encryption failed: {:?}", e),
    }

    // 4. DECRYPTION: Simulate downloading the chunk back
    let mut decrypted_buffer = vec![0u8; plaintext.len()];
    
    match core.decrypt_chunk(
        file_id, 
        cloud_id, 
        chunk_index, 
        &ciphertext_buffer, 
        &mut decrypted_buffer
    ) {
        Ok(res) => {
            assert!(res.0, "Integrity check failed!");
            println!("✅ [CRYPTO] Decrypted and Verified.");
        },
        Err(e) => panic!("❌ [CRYPTO] Decryption failed: {:?}", e),
    }

    // 5. VALIDATION: Ensure data traveled safely
    assert_eq!(plaintext.as_slice(), decrypted_buffer.as_slice());
    println!("✅ [DATA] Plaintext matches perfectly.");
}
