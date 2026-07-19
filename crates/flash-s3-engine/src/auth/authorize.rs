use flash_s3_common::{AccessControlPolicy, BucketPolicy, CanonicalUserId, FlashError, Permission};

use super::credentials::StoredKey;
use crate::storage::{BucketInfo, ObjectMeta};

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub key: Option<StoredKey>,
}

impl AuthContext {
    pub fn anonymous() -> Self {
        Self { key: None }
    }

    pub fn authenticated(key: StoredKey) -> Self {
        Self { key: Some(key) }
    }

    pub fn is_authenticated(&self) -> bool {
        self.key.is_some()
    }

    pub fn is_root(&self) -> bool {
        self.key.as_ref().is_some_and(|k| k.is_root)
    }

    pub fn access_key(&self) -> Option<&str> {
        self.key.as_ref().map(|k| k.access_key.as_str())
    }

    pub fn canonical_id(&self) -> Option<&CanonicalUserId> {
        self.key.as_ref().map(|k| &k.canonical_id)
    }

    pub fn display_name(&self) -> &str {
        self.key
            .as_ref()
            .map(|k| k.display_name.as_str())
            .unwrap_or("anonymous")
    }
}

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
    GetObject,
    PutObject,
    DeleteObject,
    GetObjectAcl,
    PutObjectAcl,
}

impl S3Action {
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
            Self::GetObject => "s3:GetObject",
            Self::PutObject => "s3:PutObject",
            Self::DeleteObject => "s3:DeleteObject",
            Self::GetObjectAcl => "s3:GetObjectAcl",
            Self::PutObjectAcl => "s3:PutObjectAcl",
        }
    }

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

pub struct Authorizer {
    pub root_bypasses: bool,
    pub auth_required: bool,
}

impl Authorizer {
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
