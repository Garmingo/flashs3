use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Minimal S3-compatible bucket policy document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BucketPolicy {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub id: Option<String>,
    pub statement: Vec<PolicyStatement>,
}

fn default_version() -> String {
    "2012-10-17".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyStatement {
    #[serde(default)]
    pub sid: Option<String>,
    pub effect: PolicyEffect,
    pub principal: PolicyPrincipal,
    pub action: StringOrVec,
    pub resource: StringOrVec,
    #[serde(default)]
    pub condition: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolicyPrincipal {
    Star(String),
    Map {
        #[serde(rename = "AWS")]
        aws: StringOrVec,
    },
}

impl PolicyPrincipal {
    pub fn matches(&self, access_key: Option<&str>) -> bool {
        match self {
            Self::Star(s) => s == "*",
            Self::Map { aws } => aws.as_slice().into_iter().any(|p| {
                if p == "*" {
                    return true;
                }
                let Some(key) = access_key else {
                    return false;
                };
                if p == key {
                    return true;
                }
                // arn:flashs3:iam:::user/<accessKey> or arn:aws:iam:::user/...
                p.rsplit('/').next() == Some(key) || wildcard_match(p, key)
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrVec {
    One(String),
    Many(Vec<String>),
}

impl StringOrVec {
    pub fn as_slice(&self) -> Vec<&str> {
        match self {
            Self::One(s) => vec![s.as_str()],
            Self::Many(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }

    pub fn matches_any(&self, value: &str) -> bool {
        self.as_slice()
            .into_iter()
            .any(|p| wildcard_match(p, value))
    }
}

/// Simple `*` / `?` wildcard match used for Action/Resource/Principal.
pub fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut p = 0usize;
    let mut v = 0usize;
    let mut star_p = None;
    let mut star_v = 0usize;
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == value[v] || pattern[p] == b'?') {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star_p = Some(p);
            star_v = v;
            p += 1;
        } else if let Some(sp) = star_p {
            p = sp + 1;
            star_v += 1;
            v = star_v;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

impl BucketPolicy {
    pub fn parse_json(raw: &str) -> Result<Self, crate::FlashError> {
        if let Ok(p) = serde_json::from_str::<Self>(raw) {
            return Ok(p);
        }
        let v: Value =
            serde_json::from_str(raw).map_err(|_| crate::FlashError::MalformedPolicy)?;
        let normalized = normalize_policy_json(v);
        serde_json::from_value(normalized).map_err(|_| crate::FlashError::MalformedPolicy)
    }

    /// Evaluate policy for an action/resource. Returns Some(true/false) if a matching
    /// statement decides, or None if no statement matched.
    pub fn evaluate(
        &self,
        action: &str,
        resource: &str,
        access_key: Option<&str>,
    ) -> Option<bool> {
        let mut denied = false;
        let mut allowed = false;
        for stmt in &self.statement {
            if !stmt.principal.matches(access_key) {
                continue;
            }
            if !stmt.action.matches_any(action) {
                continue;
            }
            if !stmt.resource.matches_any(resource) {
                continue;
            }
            match stmt.effect {
                PolicyEffect::Deny => denied = true,
                PolicyEffect::Allow => allowed = true,
            }
        }
        if denied {
            Some(false)
        } else if allowed {
            Some(true)
        } else {
            None
        }
    }
}

fn normalize_policy_json(mut v: Value) -> Value {
    if let Value::Object(map) = &mut v {
        rename_key(map, "version", "Version");
        rename_key(map, "id", "Id");
        rename_key(map, "statement", "Statement");
        if let Some(Value::Array(stmts)) = map.get_mut("Statement") {
            for s in stmts {
                if let Value::Object(sm) = s {
                    rename_key(sm, "sid", "Sid");
                    rename_key(sm, "effect", "Effect");
                    rename_key(sm, "principal", "Principal");
                    rename_key(sm, "action", "Action");
                    rename_key(sm, "resource", "Resource");
                    rename_key(sm, "condition", "Condition");
                    if let Some(Value::String(eff)) = sm.get_mut("Effect") {
                        if eff.eq_ignore_ascii_case("allow") {
                            *eff = "Allow".into();
                        } else if eff.eq_ignore_ascii_case("deny") {
                            *eff = "Deny".into();
                        }
                    }
                }
            }
        }
    }
    v
}

fn rename_key(map: &mut serde_json::Map<String, Value>, from: &str, to: &str) {
    if let Some(val) = map.remove(from) {
        map.insert(to.to_string(), val);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_basic() {
        assert!(wildcard_match("s3:Get*", "s3:GetObject"));
        assert!(wildcard_match("arn:aws:s3:::b/*", "arn:aws:s3:::b/foo"));
        assert!(!wildcard_match("s3:PutObject", "s3:GetObject"));
    }
}
