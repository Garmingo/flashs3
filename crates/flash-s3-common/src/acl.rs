use serde::{Deserialize, Serialize};

use crate::CanonicalUserId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CannedAcl {
    Private,
    PublicRead,
    PublicReadWrite,
    AuthenticatedRead,
}

impl CannedAcl {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "private" => Some(Self::Private),
            "public-read" => Some(Self::PublicRead),
            "public-read-write" => Some(Self::PublicReadWrite),
            "authenticated-read" => Some(Self::AuthenticatedRead),
            _ => None,
        }
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Permission {
    Read,
    Write,
    ReadAcp,
    WriteAcp,
    FullControl,
}

impl Permission {
    pub fn implies(self, needed: Permission) -> bool {
        if self == Permission::FullControl {
            return true;
        }
        self == needed
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::ReadAcp => "READ_ACP",
            Self::WriteAcp => "WRITE_ACP",
            Self::FullControl => "FULL_CONTROL",
        }
    }

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "PascalCase")]
pub enum Grantee {
    CanonicalUser { id: CanonicalUserId, display_name: Option<String> },
    Group { uri: GroupUri },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupUri {
    AllUsers,
    AuthenticatedUsers,
}

impl GroupUri {
    pub const ALL_USERS_URI: &'static str =
        "http://acs.amazonaws.com/groups/global/AllUsers";
    pub const AUTH_USERS_URI: &'static str =
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers";

    pub fn uri(self) -> &'static str {
        match self {
            Self::AllUsers => Self::ALL_USERS_URI,
            Self::AuthenticatedUsers => Self::AUTH_USERS_URI,
        }
    }

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub grantee: Grantee,
    pub permission: Permission,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessControlPolicy {
    pub owner: CanonicalUserId,
    pub owner_display_name: String,
    pub grants: Vec<Grant>,
}

impl AccessControlPolicy {
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

    pub fn allows(
        &self,
        principal: Option<&CanonicalUserId>,
        needed: Permission,
        authenticated: bool,
    ) -> bool {
        if principal.is_some_and(|p| p == &self.owner) && needed != Permission::WriteAcp {
            // Owner always has FULL_CONTROL via ownership for data ops; ACP still checked via grants.
        }
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
                Grantee::Group { uri: GroupUri::AllUsers } => return true,
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
