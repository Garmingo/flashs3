use serde::{Deserialize, Serialize};

/// Cache policy configured via env / CRD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum CachePolicyKind {
    None,
    #[default]
    InMemoryLru,
}

impl CachePolicyKind {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => Self::None,
            "inmemorylru" | "in_memory_lru" | "lru" => Self::InMemoryLru,
            _ => Self::InMemoryLru,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub policy: CachePolicyKind,
    pub max_size_in_bytes: u64,
    pub object_max_size_in_bytes: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            policy: CachePolicyKind::InMemoryLru,
            max_size_in_bytes: crate::env::DEFAULT_CACHE_MAX_BYTES,
            object_max_size_in_bytes: crate::env::DEFAULT_CACHE_OBJECT_MAX_BYTES,
        }
    }
}
