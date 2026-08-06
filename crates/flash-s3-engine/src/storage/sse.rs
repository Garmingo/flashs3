//! Server-side encryption SSE-S3 (AES-256-GCM).

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use flash_s3_common::FlashError;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Derive a 256-bit AES key from an optional passphrase / credentials key.
pub fn derive_sse_key(sse_key: Option<&str>, credentials_key: Option<&str>) -> [u8; 32] {
    let material = sse_key
        .or(credentials_key)
        .unwrap_or("flashs3-local-dev-sse-s3-key");
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(material.as_bytes()));
    out
}

/// Encrypt plaintext; returns (ciphertext_with_tag, base64_nonce).
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, String), FlashError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| FlashError::Internal(format!("sse key: {e}")))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| FlashError::Internal(format!("sse encrypt: {e}")))?;
    Ok((ciphertext, B64.encode(nonce_bytes)))
}

/// Decrypt ciphertext produced by [`encrypt`].
pub fn decrypt(key: &[u8; 32], nonce_b64: &str, ciphertext: &[u8]) -> Result<Vec<u8>, FlashError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| FlashError::Internal(format!("sse key: {e}")))?;
    let nonce_bytes = B64
        .decode(nonce_b64)
        .map_err(|e| FlashError::Internal(format!("sse nonce: {e}")))?;
    if nonce_bytes.len() != 12 {
        return Err(FlashError::Internal("invalid sse nonce length".into()));
    }
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| FlashError::Internal("sse decrypt failed".into()))
}

/// True when request asks for SSE-S3 AES256.
pub fn request_wants_sse_s3(headers: &http::HeaderMap) -> bool {
    headers
        .get("x-amz-server-side-encryption")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("AES256"))
}
