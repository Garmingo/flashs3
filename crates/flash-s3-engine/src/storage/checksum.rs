//! Object checksum helpers for S3 flexible checksums.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crc::{Crc, CRC_32_ISO_HDLC};
use flash_s3_common::FlashError;
use sha1::{Digest, Sha1};
use sha2::Sha256;

const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

/// Compute and optionally verify declared `x-amz-checksum-*` headers.
///
/// Returns the map of header name → base64 checksum to persist / echo.
pub fn verify_and_collect(
    body: &[u8],
    headers: &http::HeaderMap,
) -> Result<std::collections::HashMap<String, String>, FlashError> {
    let mut out = std::collections::HashMap::new();

    check_one(
        headers,
        "x-amz-checksum-crc32",
        &B64.encode(CRC32.checksum(body).to_be_bytes()),
        &mut out,
    )?;
    check_one(
        headers,
        "x-amz-checksum-crc32c",
        &B64.encode(crc32c::crc32c(body).to_be_bytes()),
        &mut out,
    )?;
    check_one(
        headers,
        "x-amz-checksum-sha1",
        &B64.encode(Sha1::digest(body)),
        &mut out,
    )?;
    check_one(
        headers,
        "x-amz-checksum-sha256",
        &B64.encode(Sha256::digest(body)),
        &mut out,
    )?;

    // Algorithm hint without value: compute and store.
    if let Some(algo) = headers
        .get("x-amz-checksum-algorithm")
        .and_then(|v| v.to_str().ok())
    {
        match algo.to_ascii_uppercase().as_str() {
            "CRC32" => {
                out.entry("x-amz-checksum-crc32".into())
                    .or_insert_with(|| B64.encode(CRC32.checksum(body).to_be_bytes()));
            }
            "CRC32C" => {
                out.entry("x-amz-checksum-crc32c".into())
                    .or_insert_with(|| B64.encode(crc32c::crc32c(body).to_be_bytes()));
            }
            "SHA1" => {
                out.entry("x-amz-checksum-sha1".into())
                    .or_insert_with(|| B64.encode(Sha1::digest(body)));
            }
            "SHA256" => {
                out.entry("x-amz-checksum-sha256".into())
                    .or_insert_with(|| B64.encode(Sha256::digest(body)));
            }
            _ => {}
        }
    }

    Ok(out)
}

fn check_one(
    headers: &http::HeaderMap,
    name: &str,
    expected_b64: &str,
    out: &mut std::collections::HashMap<String, String>,
) -> Result<(), FlashError> {
    let Some(provided) = headers.get(name).and_then(|v| v.to_str().ok()) else {
        return Ok(());
    };
    if provided != expected_b64 {
        return Err(FlashError::BadDigest);
    }
    out.insert(name.to_string(), provided.to_string());
    Ok(())
}
