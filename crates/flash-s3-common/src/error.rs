use thiserror::Error;

/// High-level error codes mapped to S3 XML by the engine.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FlashError {
    #[error("NoSuchBucket: The specified bucket does not exist")]
    NoSuchBucket,
    #[error("BucketAlreadyOwnedByYou: Your previous request to create the named bucket succeeded")]
    BucketAlreadyOwnedByYou,
    #[error("BucketNotEmpty: The bucket you tried to delete is not empty")]
    BucketNotEmpty,
    #[error("NoSuchKey: The specified key does not exist")]
    NoSuchKey,
    #[error("AccessDenied: Access Denied")]
    AccessDenied,
    #[error("InvalidAccessKeyId: The access key ID you provided does not exist")]
    InvalidAccessKeyId,
    #[error("SignatureDoesNotMatch: The request signature we calculated does not match")]
    SignatureDoesNotMatch,
    #[error("InvalidBucketName: The specified bucket is not valid")]
    InvalidBucketName,
    #[error("InvalidObjectName: The specified key is not valid")]
    InvalidObjectName,
    #[error("NoSuchUpload: The specified multipart upload does not exist")]
    NoSuchUpload,
    #[error("InvalidPart: One or more of the specified parts could not be found")]
    InvalidPart,
    #[error("EntityTooSmall: Your proposed upload is smaller than the minimum allowed size")]
    EntityTooSmall,
    #[error("MalformedACLError: The XML you provided was not well-formed")]
    MalformedAcl,
    #[error("MalformedPolicy: The policy is malformed")]
    MalformedPolicy,
    #[error("NoSuchBucketPolicy: The bucket policy does not exist")]
    NoSuchBucketPolicy,
    #[error("InvalidRequest: {0}")]
    InvalidRequest(String),
    #[error("InternalError: {0}")]
    Internal(String),
    #[error("NotImplemented: {0}")]
    NotImplemented(String),
}

impl FlashError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoSuchBucket => "NoSuchBucket",
            Self::BucketAlreadyOwnedByYou => "BucketAlreadyOwnedByYou",
            Self::BucketNotEmpty => "BucketNotEmpty",
            Self::NoSuchKey => "NoSuchKey",
            Self::AccessDenied => "AccessDenied",
            Self::InvalidAccessKeyId => "InvalidAccessKeyId",
            Self::SignatureDoesNotMatch => "SignatureDoesNotMatch",
            Self::InvalidBucketName => "InvalidBucketName",
            Self::InvalidObjectName => "InvalidObjectName",
            Self::NoSuchUpload => "NoSuchUpload",
            Self::InvalidPart => "InvalidPart",
            Self::EntityTooSmall => "EntityTooSmall",
            Self::MalformedAcl => "MalformedACLError",
            Self::MalformedPolicy => "MalformedPolicy",
            Self::NoSuchBucketPolicy => "NoSuchBucketPolicy",
            Self::InvalidRequest(_) => "InvalidRequest",
            Self::Internal(_) => "InternalError",
            Self::NotImplemented(_) => "NotImplemented",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            Self::NoSuchBucket | Self::NoSuchKey | Self::NoSuchUpload | Self::NoSuchBucketPolicy => {
                404
            }
            Self::AccessDenied | Self::InvalidAccessKeyId | Self::SignatureDoesNotMatch => 403,
            Self::BucketAlreadyOwnedByYou => 409,
            Self::BucketNotEmpty => 409,
            Self::NotImplemented(_) => 501,
            Self::Internal(_) => 500,
            _ => 400,
        }
    }
}
