//! Decoder for the S3 `aws-chunked` payload format.
//!
//! HTTP chunked transfer coding is decoded by Hyper before this layer.  AWS's
//! `aws-chunked` is different: it is part of the S3 payload and must be
//! removed before object bytes are persisted.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, ReadBuf};

use crate::auth::ChunkSigning;

/// Configuration derived from the authenticated request headers.
#[derive(Debug, Clone)]
pub struct AwsChunkedConfig {
    pub decoded_length: Option<u64>,
    pub signing: Option<ChunkSigning>,
    pub require_chunk_signatures: bool,
    pub required_trailers: Vec<String>,
    pub expected_sha256_checksum: Option<String>,
}

/// An `AsyncRead` adapter which returns only decoded S3 object bytes.
pub struct AwsChunkedReader<R> {
    inner: R,
    wire: Vec<u8>,
    remaining: usize,
    need_data_crlf: bool,
    current_hasher: Sha256,
    current_signature: Option<String>,
    decoded: u64,
    payload_hasher: Sha256,
    config: AwsChunkedConfig,
    complete: bool,
    trailers: Vec<(String, String)>,
}

/// Streaming validator for regular, fully signed (non aws-chunked) payloads.
pub struct PayloadHashReader<R> {
    inner: R,
    expected: String,
    hasher: Sha256,
    verified: bool,
}

impl<R> PayloadHashReader<R> {
    pub fn new(inner: R, expected: String) -> Self {
        Self {
            inner,
            expected,
            hasher: Sha256::new(),
            verified: false,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PayloadHashReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.verified {
            return Poll::Ready(Ok(()));
        }
        let initial_len = out.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, out) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let received = &out.filled()[initial_len..];
                if received.is_empty() {
                    let actual = hex::encode(self.hasher.clone().finalize());
                    if actual != self.expected {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "x-amz-content-sha256 does not match payload",
                        )));
                    }
                    self.verified = true;
                } else {
                    self.hasher.update(received);
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<R> AwsChunkedReader<R> {
    pub fn new(inner: R, config: AwsChunkedConfig) -> Self {
        Self {
            inner,
            wire: Vec::new(),
            remaining: 0,
            need_data_crlf: false,
            current_hasher: Sha256::new(),
            current_signature: None,
            decoded: 0,
            payload_hasher: Sha256::new(),
            config,
            complete: false,
            trailers: Vec::new(),
        }
    }

    fn error(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message.into())
    }

    fn take_line(&mut self) -> Option<Vec<u8>> {
        let end = self.wire.windows(2).position(|window| window == b"\r\n")?;
        let line = self.wire[..end].to_vec();
        self.wire.drain(..end + 2);
        Some(line)
    }

    fn parse_chunk_header(&mut self, line: &[u8]) -> io::Result<bool> {
        let line = std::str::from_utf8(line).map_err(|_| Self::error("invalid aws-chunked header"))?;
        let (size, extensions) = line.split_once(';').unwrap_or((line, ""));
        if size.is_empty() || size.len() > 16 {
            return Err(Self::error("invalid aws-chunked chunk size"));
        }
        let size = usize::from_str_radix(size, 16)
            .map_err(|_| Self::error("invalid aws-chunked chunk size"))?;
        let signature = extensions
            .split(';')
            .find_map(|extension| extension.strip_prefix("chunk-signature="))
            .map(ToOwned::to_owned);

        if self.config.require_chunk_signatures && signature.is_none() {
            return Err(Self::error("missing aws-chunked chunk signature"));
        }
        if signature.as_ref().is_some_and(|value| {
            value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) {
            return Err(Self::error("invalid aws-chunked chunk signature"));
        }

        self.remaining = size;
        self.current_hasher = Sha256::new();
        self.current_signature = signature;
        Ok(size == 0)
    }

    fn verify_current_chunk(&mut self) -> io::Result<()> {
        let Some(signature) = self.current_signature.take() else {
            return Ok(());
        };
        let signing = self
            .config
            .signing
            .as_mut()
            .ok_or_else(|| Self::error("signed aws-chunked payload lacks signing context"))?;
        let payload_hash = hex::encode(self.current_hasher.clone().finalize());
        signing.verify_chunk(&payload_hash, &signature)
            .map_err(|_| Self::error("aws-chunked chunk signature mismatch"))
    }

    fn finish(&mut self) -> io::Result<()> {
        if let Some(expected) = self.config.decoded_length {
            if self.decoded != expected {
                return Err(Self::error("x-amz-decoded-content-length does not match payload"));
            }
        }
        for name in &self.config.required_trailers {
            if self
                .trailers
                .iter()
                .filter(|(trailer_name, _)| trailer_name == name)
                .count()
                != 1
            {
                return Err(Self::error("missing or duplicate declared aws-chunked trailer"));
            }
        }
        let expected_checksum = self
            .config
            .expected_sha256_checksum
            .as_deref()
            .or_else(|| {
                self.trailers
                    .iter()
                    .find(|(name, _)| name == "x-amz-checksum-sha256")
                    .map(|(_, value)| value.as_str())
            });
        if let Some(expected) = expected_checksum {
            let actual = base64::engine::general_purpose::STANDARD
                .encode(self.payload_hasher.clone().finalize());
            if actual != expected {
                return Err(Self::error("x-amz-checksum-sha256 mismatch"));
            }
        }
        self.complete = true;
        Ok(())
    }
}

impl<R: AsyncRead + Unpin> AwsChunkedReader<R> {
    fn poll_fill_wire(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let mut scratch = [0u8; 16 * 1024];
        let mut read_buf = ReadBuf::new(&mut scratch);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                if read_buf.filled().is_empty() {
                    Poll::Ready(Ok(false))
                } else {
                    self.wire.extend_from_slice(read_buf.filled());
                    Poll::Ready(Ok(true))
                }
            }
        }
    }

    fn poll_need_line(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Vec<u8>>> {
        loop {
            if let Some(line) = self.take_line() {
                return Poll::Ready(Ok(line));
            }
            match self.poll_fill_wire(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(false)) => {
                    return Poll::Ready(Err(Self::error("unexpected EOF in aws-chunked payload")));
                }
                Poll::Ready(Ok(true)) => {}
            }
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for AwsChunkedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.complete {
            return Poll::Ready(Ok(()));
        }

        loop {
            if self.remaining > 0 {
                if self.wire.is_empty() {
                    match self.poll_fill_wire(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(Self::error(
                                "unexpected EOF in aws-chunked chunk data",
                            )));
                        }
                        Poll::Ready(Ok(true)) => {}
                    }
                }
                let count = self.remaining.min(self.wire.len()).min(out.remaining());
                if count == 0 {
                    return Poll::Ready(Ok(()));
                }
                let bytes = self.wire[..count].to_vec();
                self.wire.drain(..count);
                self.remaining -= count;
                self.decoded += count as u64;
                self.current_hasher.update(&bytes);
                self.payload_hasher.update(&bytes);
                out.put_slice(&bytes);
                if self.remaining == 0 {
                    self.need_data_crlf = true;
                }
                return Poll::Ready(Ok(()));
            }

            if self.need_data_crlf {
                let line = match self.poll_need_line(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result?,
                };
                if !line.is_empty() {
                    return Poll::Ready(Err(Self::error("missing CRLF after aws-chunked data")));
                }
                self.verify_current_chunk()?;
                self.need_data_crlf = false;
            }

            let line = match self.poll_need_line(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result?,
            };
            if self.parse_chunk_header(&line)? {
                self.verify_current_chunk()?;
                loop {
                    let trailer = match self.poll_need_line(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(result) => result?,
                    };
                    if trailer.is_empty() {
                        self.finish()?;
                        return Poll::Ready(Ok(()));
                    }
                    let trailer = std::str::from_utf8(&trailer)
                        .map_err(|_| Self::error("invalid aws-chunked trailer"))?;
                    let (name, value) = trailer
                        .split_once(':')
                        .ok_or_else(|| Self::error("invalid aws-chunked trailer"))?;
                    self.trailers
                        .push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use sha2::Digest;
    use tokio::io::AsyncReadExt;

    use super::{AwsChunkedConfig, AwsChunkedReader};

    #[tokio::test]
    async fn strips_frames_and_preserves_payload() {
        let wire = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut reader = AwsChunkedReader::new(
            &wire[..],
            AwsChunkedConfig {
                decoded_length: Some(11),
                signing: None,
                require_chunk_signatures: false,
                required_trailers: Vec::new(),
                expected_sha256_checksum: None,
            },
        );
        let mut data = Vec::new();
        reader.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"hello world");
    }

    #[tokio::test]
    async fn rejects_wrong_decoded_length() {
        let wire = b"1\r\na\r\n0\r\n\r\n";
        let mut reader = AwsChunkedReader::new(
            &wire[..],
            AwsChunkedConfig {
                decoded_length: Some(2),
                signing: None,
                require_chunk_signatures: false,
                required_trailers: Vec::new(),
                expected_sha256_checksum: None,
            },
        );
        assert!(reader.read_to_end(&mut Vec::new()).await.is_err());
    }

    #[tokio::test]
    async fn validates_declared_sha256_trailer() {
        let checksum = base64::engine::general_purpose::STANDARD
            .encode(sha2::Sha256::digest(b"hello"));
        let wire = format!(
            "5\r\nhello\r\n0\r\nx-amz-checksum-sha256:{checksum}\r\n\r\n"
        );
        let mut reader = AwsChunkedReader::new(
            wire.as_bytes(),
            AwsChunkedConfig {
                decoded_length: Some(5),
                signing: None,
                require_chunk_signatures: false,
                required_trailers: vec!["x-amz-checksum-sha256".into()],
                expected_sha256_checksum: None,
            },
        );
        let mut data = Vec::new();
        reader.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"hello");
    }
}
