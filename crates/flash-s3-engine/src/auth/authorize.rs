//! Authorization: bucket policies first, then classic S3 ACLs.
//!
//! Evaluation order (see plan):
//! 1. Policy Deny
//! 2. Policy Allow
//! 3. ACL grants (object then bucket)
//! 4. Default Deny
//!
//! Root keys may bypass when [`Authorizer::root_bypasses`] is true.

use flash_s3_common::{AccessControlPolicy, BucketPolicy, CanonicalUserId, FlashError, Permission};

use super::credentials::StoredKey;
use super::sigv4::ChunkSigning;
use crate::storage::{BucketInfo, ObjectMeta};

/// Authenticated (or anonymous) caller for a single request.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Present when SigV4 succeeded.
    pub key: Option<StoredKey>,
    /// Per-request key material for SigV4 streaming chunks.
    pub streaming: Option<ChunkSigning>,
}

impl AuthContext {
    /// Anonymous (unsigned) caller.
    pub fn anonymous() -> Self {
        Self {
            key: None,
            streaming: None,
        }
    }

    /// Caller authenticated with `key`.
    pub fn authenticated(key: StoredKey) -> Self {
        Self {
            key: Some(key),
            streaming: None,
        }
    }

    /// Caller authenticated with streaming SigV4 context.
    pub fn authenticated_streaming(key: StoredKey, streaming: Option<ChunkSigning>) -> Self {
        Self {
            key: Some(key),
            streaming,
        }
    }

    /// True when SigV4 produced a key.
    pub fn is_authenticated(&self) -> bool {
        self.key.is_some()
    }

    /// True for root/bootstrap credentials.
    pub fn is_root(&self) -> bool {
        self.key.as_ref().is_some_and(|k| k.is_root)
    }

    /// Access key id for policy principal matching.
    pub fn access_key(&self) -> Option<&str> {
        self.key.as_ref().map(|k| k.access_key.as_str())
    }

    /// Canonical user id for ACL checks.
    pub fn canonical_id(&self) -> Option<&CanonicalUserId> {
        self.key.as_ref().map(|k| &k.canonical_id)
    }

    /// Display name or `"anonymous"`.
    pub fn display_name(&self) -> &str {
        self.key
            .as_ref()
            .map(|k| k.display_name.as_str())
            .unwrap_or("anonymous")
    }
}

/// Logical S3 action used for policy action strings and ACL permission mapping.
#[derive(Debug, Clone, Copy)]
pub enum S3Action {
    ListBuckets,
    CreateBucket,
    DeleteBucket,
    HeadBucket,
    ListBucket,
    GetBucketAcl,
    PutBucketAcl,
    GetBucketPolicy,
    PutBucketPolicy,
    DeleteBucketPolicy,
    GetBucketCors,
    PutBucketCors,
    DeleteBucketCors,
    GetObject,
    PutObject,
    DeleteObject,
    GetObjectAcl,
    PutObjectAcl,
}

impl S3Action {
    /// IAM-style action string, e.g. `s3:GetObject`.
    pub fn as_policy_action(self) -> &'static str {
        match self {
            Self::ListBuckets => "s3:ListAllMyBuckets",
            Self::CreateBucket => "s3:CreateBucket",
            Self::DeleteBucket => "s3:DeleteBucket",
            Self::HeadBucket => "s3:ListBucket",
            Self::ListBucket => "s3:ListBucket",
            Self::GetBucketAcl => "s3:GetBucketAcl",
            Self::PutBucketAcl => "s3:PutBucketAcl",
            Self::GetBucketPolicy => "s3:GetBucketPolicy",
            Self::PutBucketPolicy => "s3:PutBucketPolicy",
            Self::DeleteBucketPolicy => "s3:DeleteBucketPolicy",
            Self::GetBucketCors => "s3:GetBucketCors",
            Self::PutBucketCors => "s3:PutBucketCors",
            Self::DeleteBucketCors => "s3:DeleteBucketCors",
            Self::GetObject => "s3:GetObject",
            Self::PutObject => "s3:PutObject",
            Self::DeleteObject => "s3:DeleteObject",
            Self::GetObjectAcl => "s3:GetObjectAcl",
            Self::PutObjectAcl => "s3:PutObjectAcl",
        }
    }

    /// ACL permission bit required for this action, if ACL-governed.
    pub fn acl_permission(self) -> Option<Permission> {
        match self {
            Self::GetObject | Self::ListBucket | Self::HeadBucket => Some(Permission::Read),
            Self::PutObject | Self::DeleteObject | Self::CreateBucket => Some(Permission::Write),
            Self::GetBucketAcl | Self::GetObjectAcl => Some(Permission::ReadAcp),
            Self::PutBucketAcl | Self::PutObjectAcl => Some(Permission::WriteAcp),
            _ => None,
        }
    }
}

/// Policy + ACL decision engine.
pub struct Authorizer {
    /// When true, `is_root` keys skip ACL/policy checks.
    pub root_bypasses: bool,
    /// Reserved for stricter anonymous handling.
    pub auth_required: bool,
}

impl Authorizer {
    /// Authorize service-level ops (ListBuckets / CreateBucket).
    pub fn check_service(&self, ctx: &AuthContext, action: S3Action) -> Result<(), FlashError> {
        if matches!(
            action,
            S3Action::ListBuckets | S3Action::CreateBucket
        ) {
            if ctx.is_authenticated() {
                return Ok(());
            }
            if self.auth_required || ctx.key.is_none() {
                // Create/ListBuckets always need auth when keys exist handled by caller
                return Err(FlashError::AccessDenied);
            }
        }
        Ok(())
    }

    /// Authorize a bucket/object action for `ctx`.
    pub fn authorize(
        &self,
        ctx: &AuthContext,
        action: S3Action,
        bucket: Option<&BucketInfo>,
        object: Option<&ObjectMeta>,
        policy: Option<&BucketPolicy>,
    ) -> Result<(), FlashError> {
        if self.root_bypasses && ctx.is_root() {
            return Ok(());
        }

        let resource = if let (Some(b), Some(o)) = (bucket, object) {
            format!("arn:aws:s3:::{}/{}", b.name, o.key)
        } else if let Some(b) = bucket {
            format!("arn:aws:s3:::{}", b.name)
        } else {
            "arn:aws:s3:::".to_string()
        };

        if let Some(pol) = policy {
            if let Some(decision) =
                pol.evaluate(action.as_policy_action(), &resource, ctx.access_key())
            {
                return if decision {
                    Ok(())
                } else {
                    Err(FlashError::AccessDenied)
                };
            }
            // Also try wildcard object resource for GetObject etc.
            if let Some(b) = bucket {
                let wild = format!("arn:aws:s3:::{}/*", b.name);
                if let Some(decision) =
                    pol.evaluate(action.as_policy_action(), &wild, ctx.access_key())
                {
                    return if decision {
                        Ok(())
                    } else {
                        Err(FlashError::AccessDenied)
                    };
                }
            }
        }

        if let Some(needed) = action.acl_permission() {
            // Object ACL first for object ops, else bucket ACL
            if let Some(obj) = object {
                if matches!(
                    action,
                    S3Action::GetObject
                        | S3Action::PutObject
                        | S3Action::DeleteObject
                        | S3Action::GetObjectAcl
                        | S3Action::PutObjectAcl
                ) {
                    if obj.acl.allows(
                        ctx.canonical_id(),
                        needed,
                        ctx.is_authenticated(),
                    ) {
                        return Ok(());
                    }
                    return Err(FlashError::AccessDenied);
                }
            }
            if let Some(b) = bucket {
                if b.acl
                    .allows(ctx.canonical_id(), needed, ctx.is_authenticated())
                {
                    return Ok(());
                }
                return Err(FlashError::AccessDenied);
            }
        }

        // Default: authenticated users can manage when no ACL needed
        if ctx.is_authenticated() {
            return Ok(());
        }
        Err(FlashError::AccessDenied)
    }

    /// Ensure the caller may replace an ACL (owner or `WRITE_ACP`).
    pub fn ensure_can_set_acl(
        &self,
        ctx: &AuthContext,
        acl: &AccessControlPolicy,
    ) -> Result<(), FlashError> {
        if self.root_bypasses && ctx.is_root() {
            return Ok(());
        }
        if ctx.canonical_id() == Some(&acl.owner) {
            return Ok(());
        }
        if acl.allows(
            ctx.canonical_id(),
            Permission::WriteAcp,
            ctx.is_authenticated(),
        ) {
            return Ok(());
        }
        Err(FlashError::AccessDenied)
    }
}
