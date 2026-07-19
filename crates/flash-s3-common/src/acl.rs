//! Classic S3 Access Control Lists (canned ACLs + grant lists).
//!
//! FlashS3 stores these on buckets (`bucket.json`) and objects (`meta.json`).
//! Evaluation happens after bucket policies (deny/allow) in the engine authorizer.

use serde::{Deserialize, Serialize};

use crate::CanonicalUserId;

/// Well-known canned ACL names accepted via `x-amz-acl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CannedAcl {
    /// Owner full control only (default).
    Private,
    /// Anonymous clients may read object/bucket data.
    PublicRead,
    /// Anonymous clients may read and write data (dangerous; supported for S3 parity).
    PublicReadWrite,
    /// Any authenticated API key may read.
    AuthenticatedRead,
}

impl CannedAcl {
    /// Parse a canned ACL header/query value.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "private" => Some(Self::Private),
            "public-read" => Some(Self::PublicRead),
            "public-read-write" => Some(Self::PublicReadWrite),
            "authenticated-read" => Some(Self::AuthenticatedRead),
            _ => None,
        }
    }

    /// Wire-format string (`private`, `public-read`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::PublicRead => "public-read",
            Self::PublicReadWrite => "public-read-write",
            Self::AuthenticatedRead => "authenticated-read",
        }
    }
}

impl Default for CannedAcl {
    fn default() -> Self {
        Self::Private
    }
}

/// S3 ACL permission bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Permission {
    /// Read object data / list bucket.
    Read,
    /// Write/overwrite/delete data.
    Write,
    /// Read the ACL document itself.
    ReadAcp,
    /// Replace the ACL document.
    WriteAcp,
    /// All of the above.
    FullControl,
}

impl Permission {
    /// Returns true if `self` satisfies a required permission.
    ///
    /// `FullControl` implies every other permission.
    pub fn implies(self, needed: Permission) -> bool {
        if self == Permission::FullControl {
            return true;
        }
        self == needed
    }

    /// S3 XML permission token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::ReadAcp => "READ_ACP",
            Self::WriteAcp => "WRITE_ACP",
            Self::FullControl => "FULL_CONTROL",
        }
    }

    /// Parse an S3 permission token.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "READ" => Some(Self::Read),
            "WRITE" => Some(Self::Write),
            "READ_ACP" => Some(Self::ReadAcp),
            "WRITE_ACP" => Some(Self::WriteAcp),
            "FULL_CONTROL" => Some(Self::FullControl),
            _ => None,
        }
    }
}

/// Who a grant is issued to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "PascalCase")]
pub enum Grantee {
    /// A specific FlashS3 API key, identified by its canonical user id.
    CanonicalUser {
        /// Stable id (SHA-256 of access key at creation time).
        id: CanonicalUserId,
        /// Optional human-readable name.
        display_name: Option<String>,
    },
    /// Predefined group (`AllUsers` / `AuthenticatedUsers`).
    Group {
        /// Group URI enum.
        uri: GroupUri,
    },
}

/// Predefined S3 ACL groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupUri {
    /// Anyone on the internet (anonymous).
    AllUsers,
    /// Any request that authenticated with a valid API key.
    AuthenticatedUsers,
}

impl GroupUri {
    /// AWS AllUsers group URI.
    pub const ALL_USERS_URI: &'static str =
        "http://acs.amazonaws.com/groups/global/AllUsers";
    /// AWS AuthenticatedUsers group URI.
    pub const AUTH_USERS_URI: &'static str =
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers";

    /// Full URI string used in ACL XML.
    pub fn uri(self) -> &'static str {
        match self {
            Self::AllUsers => Self::ALL_USERS_URI,
            Self::AuthenticatedUsers => Self::AUTH_USERS_URI,
        }
    }

    /// Parse from a full or suffix-matched URI.
    pub fn parse(uri: &str) -> Option<Self> {
        if uri.ends_with("AllUsers") {
            Some(Self::AllUsers)
        } else if uri.ends_with("AuthenticatedUsers") {
            Some(Self::AuthenticatedUsers)
        } else {
            None
        }
    }
}

/// Single ACL grant: grantee + permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// Subject of the grant.
    pub grantee: Grantee,
    /// Permission granted.
    pub permission: Permission,
}

/// Full Access Control Policy (owner + grant list).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessControlPolicy {
    /// Resource owner canonical id.
    pub owner: CanonicalUserId,
    /// Owner display name for XML responses.
    pub owner_display_name: String,
    /// Explicit grants (always includes owner FULL_CONTROL when built from canned).
    pub grants: Vec<Grant>,
}

impl AccessControlPolicy {
    /// Expand a canned ACL into an owner + grant list.
    pub fn from_canned(owner: CanonicalUserId, display_name: &str, canned: CannedAcl) -> Self {
        let mut grants = vec![Grant {
            grantee: Grantee::CanonicalUser {
                id: owner.clone(),
                display_name: Some(display_name.to_string()),
            },
            permission: Permission::FullControl,
        }];
        match canned {
            CannedAcl::Private => {}
            CannedAcl::PublicRead => {
                grants.push(Grant {
                    grantee: Grantee::Group {
                        uri: GroupUri::AllUsers,
                    },
                    permission: Permission::Read,
                });
            }
            CannedAcl::PublicReadWrite => {
                grants.push(Grant {
                    grantee: Grantee::Group {
                        uri: GroupUri::AllUsers,
                    },
                    permission: Permission::Read,
                });
                grants.push(Grant {
                    grantee: Grantee::Group {
                        uri: GroupUri::AllUsers,
                    },
                    permission: Permission::Write,
                });
            }
            CannedAcl::AuthenticatedRead => {
                grants.push(Grant {
                    grantee: Grantee::Group {
                        uri: GroupUri::AuthenticatedUsers,
                    },
                    permission: Permission::Read,
                });
            }
        }
        Self {
            owner,
            owner_display_name: display_name.to_string(),
            grants,
        }
    }

    /// Check whether `principal` may perform `needed`.
    ///
    /// - Resource **owner** always allowed.
    /// - `AllUsers` grants apply to anonymous and authenticated callers.
    /// - `AuthenticatedUsers` requires `authenticated == true`.
    pub fn allows(
        &self,
        principal: Option<&CanonicalUserId>,
        needed: Permission,
        authenticated: bool,
    ) -> bool {
        if principal.is_some_and(|p| p == &self.owner) {
            return true;
        }
        for g in &self.grants {
            if !g.permission.implies(needed) {
                continue;
            }
            match &g.grantee {
                Grantee::CanonicalUser { id, .. } => {
                    if principal.is_some_and(|p| p == id) {
                        return true;
                    }
                }
                Grantee::Group {
                    uri: GroupUri::AllUsers,
                } => return true,
                Grantee::Group {
                    uri: GroupUri::AuthenticatedUsers,
                } => {
                    if authenticated {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> CanonicalUserId {
        CanonicalUserId::new("owner-1")
    }

    #[test]
    fn canned_private_denies_anonymous_read() {
        let acl = AccessControlPolicy::from_canned(owner(), "root", CannedAcl::Private);
        assert!(!acl.allows(None, Permission::Read, false));
        assert!(acl.allows(Some(&owner()), Permission::Read, true));
    }

    #[test]
    fn canned_public_read_allows_anonymous() {
        let acl = AccessControlPolicy::from_canned(owner(), "root", CannedAcl::PublicRead);
        assert!(acl.allows(None, Permission::Read, false));
        assert!(!acl.allows(None, Permission::Write, false));
    }

    #[test]
    fn canned_public_read_write_allows_anon_write() {
        let acl = AccessControlPolicy::from_canned(owner(), "root", CannedAcl::PublicReadWrite);
        assert!(acl.allows(None, Permission::Write, false));
    }

    #[test]
    fn authenticated_read_requires_auth() {
        let acl = AccessControlPolicy::from_canned(owner(), "root", CannedAcl::AuthenticatedRead);
        assert!(!acl.allows(None, Permission::Read, false));
        let other = CanonicalUserId::new("other");
        assert!(acl.allows(Some(&other), Permission::Read, true));
    }

    #[test]
    fn full_control_implies_all() {
        assert!(Permission::FullControl.implies(Permission::Read));
        assert!(Permission::FullControl.implies(Permission::WriteAcp));
        assert!(!Permission::Read.implies(Permission::Write));
    }

    #[test]
    fn parse_canned_and_permission_roundtrip() {
        assert_eq!(CannedAcl::parse("public-read"), Some(CannedAcl::PublicRead));
        assert_eq!(CannedAcl::PublicRead.as_str(), "public-read");
        assert_eq!(Permission::parse("READ_ACP"), Some(Permission::ReadAcp));
        assert_eq!(GroupUri::parse(GroupUri::ALL_USERS_URI), Some(GroupUri::AllUsers));
    }

    #[test]
    fn canonical_grantee_match() {
        let alice = CanonicalUserId::new("alice");
        let mut acl = AccessControlPolicy::from_canned(owner(), "root", CannedAcl::Private);
        acl.grants.push(Grant {
            grantee: Grantee::CanonicalUser {
                id: alice.clone(),
                display_name: Some("Alice".into()),
            },
            permission: Permission::Read,
        });
        assert!(acl.allows(Some(&alice), Permission::Read, true));
        assert!(!acl.allows(Some(&alice), Permission::Write, true));
    }
}
