//! Portable error codes that the engine maps to S3 XML error responses.

use thiserror::Error;

/// High-level FlashS3 / S3 error codes.
///
/// The engine translates these into HTTP status + `<Error><Code>…</Code>` XML.
/// Keep variants stable; clients and SDKs key off the code string.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FlashError {
    /// Target bucket does not exist.
    #[error("NoSuchBucket: The specified bucket does not exist")]
    NoSuchBucket,
    /// CreateBucket on a name you already own.
    #[error("BucketAlreadyOwnedByYou: Your previous request to create the named bucket succeeded")]
    BucketAlreadyOwnedByYou,
    /// DeleteBucket refused because objects remain.
    #[error("BucketNotEmpty: The bucket you tried to delete is not empty")]
    BucketNotEmpty,
    /// Object key not found.
    #[error("NoSuchKey: The specified key does not exist")]
    NoSuchKey,
    /// Authorization failed (ACL, policy, or missing credentials).
    #[error("AccessDenied: Access Denied")]
    AccessDenied,
    /// Unknown or disabled access key.
    #[error("InvalidAccessKeyId: The access key ID you provided does not exist")]
    InvalidAccessKeyId,
    /// SigV4 signature mismatch or malformed auth header.
    #[error("SignatureDoesNotMatch: The request signature we calculated does not match")]
    SignatureDoesNotMatch,
    /// Content-MD5 or a declared object checksum did not match the payload.
    #[error("BadDigest: The Content-MD5 you specified did not match what we received")]
    BadDigest,
    /// Signed SHA-256 payload hash did not match the received body.
    #[error("XAmzContentSHA256Mismatch: The provided x-amz-content-sha256 does not match")]
    ContentSha256Mismatch,
    /// Bucket name violates naming rules.
    #[error("InvalidBucketName: The specified bucket is not valid")]
    InvalidBucketName,
    /// Object key invalid (empty, `..`, too long, …).
    #[error("InvalidObjectName: The specified key is not valid")]
    InvalidObjectName,
    /// Multipart upload id unknown.
    #[error("NoSuchUpload: The specified multipart upload does not exist")]
    NoSuchUpload,
    /// Listed part missing or ETag mismatch on complete.
    #[error("InvalidPart: One or more of the specified parts could not be found")]
    InvalidPart,
    /// Multipart completion list is not strictly ascending.
    #[error("InvalidPartOrder: The list of parts was not in ascending order")]
    InvalidPartOrder,
    /// Upload below minimum size (reserved for future strict checks).
    #[error("EntityTooSmall: Your proposed upload is smaller than the minimum allowed size")]
    EntityTooSmall,
    /// ACL XML could not be parsed.
    #[error("MalformedACLError: The XML you provided was not well-formed")]
    MalformedAcl,
    /// Bucket policy JSON invalid.
    #[error("MalformedPolicy: The policy is malformed")]
    MalformedPolicy,
    /// No policy attached to the bucket.
    #[error("NoSuchBucketPolicy: The bucket policy does not exist")]
    NoSuchBucketPolicy,
    /// CORS XML could not be parsed or failed validation.
    #[error("MalformedXML: The CORS configuration XML is malformed")]
    MalformedCORSConfiguration,
    /// No CORS configuration attached to the bucket.
    #[error("NoSuchCORSConfiguration: The CORS configuration does not exist")]
    NoSuchCORSConfiguration,
    /// Generic client error with detail message.
    #[error("InvalidRequest: {0}")]
    InvalidRequest(String),
    /// Unexpected internal failure (I/O, corrupt meta, …).
    #[error("InternalError: {0}")]
    Internal(String),
    /// Intentionally unsupported API surface.
    #[error("NotImplemented: {0}")]
    NotImplemented(String),
}

impl FlashError {
    /// S3 `<Code>` string for XML error bodies.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoSuchBucket => "NoSuchBucket",
            Self::BucketAlreadyOwnedByYou => "BucketAlreadyOwnedByYou",
            Self::BucketNotEmpty => "BucketNotEmpty",
            Self::NoSuchKey => "NoSuchKey",
            Self::AccessDenied => "AccessDenied",
            Self::InvalidAccessKeyId => "InvalidAccessKeyId",
            Self::SignatureDoesNotMatch => "SignatureDoesNotMatch",
            Self::BadDigest => "BadDigest",
            Self::ContentSha256Mismatch => "XAmzContentSHA256Mismatch",
            Self::InvalidBucketName => "InvalidBucketName",
            Self::InvalidObjectName => "InvalidObjectName",
            Self::NoSuchUpload => "NoSuchUpload",
            Self::InvalidPart => "InvalidPart",
            Self::InvalidPartOrder => "InvalidPartOrder",
            Self::EntityTooSmall => "EntityTooSmall",
            Self::MalformedAcl => "MalformedACLError",
            Self::MalformedPolicy => "MalformedPolicy",
            Self::NoSuchBucketPolicy => "NoSuchBucketPolicy",
            Self::MalformedCORSConfiguration => "MalformedXML",
            Self::NoSuchCORSConfiguration => "NoSuchCORSConfiguration",
            Self::InvalidRequest(_) => "InvalidRequest",
            Self::Internal(_) => "InternalError",
            Self::NotImplemented(_) => "NotImplemented",
        }
    }

    /// Suggested HTTP status code for this error.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::NoSuchBucket
            | Self::NoSuchKey
            | Self::NoSuchUpload
            | Self::NoSuchBucketPolicy
            | Self::NoSuchCORSConfiguration => 404,
            Self::AccessDenied | Self::InvalidAccessKeyId | Self::SignatureDoesNotMatch => 403,
            Self::BucketAlreadyOwnedByYou => 409,
            Self::BucketNotEmpty => 409,
            Self::NotImplemented(_) => 501,
            Self::Internal(_) => 500,
            _ => 400,
        }
    }
}
