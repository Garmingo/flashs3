//! Minimal hand-rolled S3 XML serializers/parsers for responses we support.
//!
//! Avoiding a heavy schema stack keeps the binary small; parsers are intentionally
//! tolerant rather than fully XSD-compliant.

use flash_s3_common::{AccessControlPolicy, Grantee, GroupUri};

use super::error::xml_escape;
use crate::storage::{BucketInfo, IndexEntry};

/// `ListAllMyBucketsResult` body.
pub fn list_buckets_xml(buckets: &[BucketInfo], owner_id: &str, owner_name: &str) -> String {
    let mut body = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    body.push_str(&format!(
        "<Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner><Buckets>",
        xml_escape(owner_id),
        xml_escape(owner_name)
    ));
    for b in buckets {
        body.push_str(&format!(
            "<Bucket><Name>{}</Name><CreationDate>{}</CreationDate></Bucket>",
            xml_escape(&b.name),
            xml_escape(&b.created)
        ));
    }
    body.push_str("</Buckets></ListAllMyBucketsResult>");
    body
}

/// `ListBucketResult` body (ListObjectsV2-shaped).
pub fn list_objects_v2_xml(
    bucket: &str,
    prefix: &str,
    max_keys: usize,
    truncated: bool,
    contents: &[IndexEntry],
    next_token: Option<&str>,
) -> String {
    let mut body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>{}</Name><Prefix>{}</Prefix><MaxKeys>{}</MaxKeys><IsTruncated>{}</IsTruncated><KeyCount>{}</KeyCount>"#,
        xml_escape(bucket),
        xml_escape(prefix),
        max_keys,
        truncated,
        contents.len()
    );
    if let Some(t) = next_token {
        body.push_str(&format!(
            "<NextContinuationToken>{}</NextContinuationToken>",
            xml_escape(t)
        ));
    }
    for c in contents {
        body.push_str(&format!(
            "<Contents><Key>{}</Key><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
            xml_escape(&c.key),
            xml_escape(&c.last_modified),
            xml_escape(&c.etag),
            c.size
        ));
    }
    body.push_str("</ListBucketResult>");
    body
}

/// `AccessControlPolicy` XML for GetBucketAcl / GetObjectAcl.
pub fn acl_xml(acl: &AccessControlPolicy) -> String {
    let mut body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner><AccessControlList>"#,
        xml_escape(acl.owner.as_str()),
        xml_escape(&acl.owner_display_name)
    );
    for g in &acl.grants {
        body.push_str("<Grant>");
        match &g.grantee {
            Grantee::CanonicalUser { id, display_name } => {
                body.push_str(&format!(
                    r#"<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>{}</ID><DisplayName>{}</DisplayName></Grantee>"#,
                    xml_escape(id.as_str()),
                    xml_escape(display_name.as_deref().unwrap_or(""))
                ));
            }
            Grantee::Group { uri } => {
                body.push_str(&format!(
                    r#"<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI>{}</URI></Grantee>"#,
                    xml_escape(uri.uri())
                ));
            }
        }
        body.push_str(&format!(
            "<Permission>{}</Permission></Grant>",
            g.permission.as_str()
        ));
    }
    body.push_str("</AccessControlList></AccessControlPolicy>");
    body
}

/// Best-effort ACL XML parser for PutBucketAcl / PutObjectAcl bodies.
pub fn parse_acl_xml(raw: &str, fallback_owner: &AccessControlPolicy) -> Result<AccessControlPolicy, flash_s3_common::FlashError> {
    // Minimal parser for grants; if parse fails, return MalformedAcl
    let mut grants = Vec::new();
    let mut owner = fallback_owner.owner.clone();
    let mut owner_display = fallback_owner.owner_display_name.clone();

    if let Some(id) = extract_tag(raw, "ID") {
        if raw.contains("<Owner>") {
            if let Some(owner_block) = extract_block(raw, "Owner") {
                if let Some(oid) = extract_tag(&owner_block, "ID") {
                    owner = flash_s3_common::CanonicalUserId::new(oid);
                }
                if let Some(dn) = extract_tag(&owner_block, "DisplayName") {
                    owner_display = dn;
                }
            }
        }
        let _ = id;
    }

    let mut rest = raw;
    while let Some(grant) = extract_block(rest, "Grant") {
        let perm_s = extract_tag(&grant, "Permission")
            .ok_or(flash_s3_common::FlashError::MalformedAcl)?;
        let permission = flash_s3_common::Permission::parse(&perm_s)
            .ok_or(flash_s3_common::FlashError::MalformedAcl)?;
        let grantee = if grant.contains("AllUsers") || grant.contains(&GroupUri::ALL_USERS_URI.to_string()) {
            Grantee::Group {
                uri: GroupUri::AllUsers,
            }
        } else if grant.contains("AuthenticatedUsers") {
            Grantee::Group {
                uri: GroupUri::AuthenticatedUsers,
            }
        } else if let Some(id) = extract_tag(&grant, "ID") {
            Grantee::CanonicalUser {
                id: flash_s3_common::CanonicalUserId::new(id),
                display_name: extract_tag(&grant, "DisplayName"),
            }
        } else {
            return Err(flash_s3_common::FlashError::MalformedAcl);
        };
        grants.push(flash_s3_common::Grant { grantee, permission });
        if let Some(idx) = rest.find("</Grant>") {
            rest = &rest[idx + 8..];
        } else {
            break;
        }
    }

    if grants.is_empty() {
        return Err(flash_s3_common::FlashError::MalformedAcl);
    }

    Ok(AccessControlPolicy {
        owner,
        owner_display_name: owner_display,
        grants,
    })
}

fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let start = format!("<{tag}>");
    let end = format!("</{tag}>");
    let i = xml.find(&start)? + start.len();
    let j = xml[i..].find(&end)? + i;
    Some(xml[i..j].to_string())
}

fn extract_block(xml: &str, tag: &str) -> Option<String> {
    let start = format!("<{tag}>");
    let end = format!("</{tag}>");
    let i = xml.find(&start)?;
    let j = xml[i..].find(&end)? + i + end.len();
    Some(xml[i..j].to_string())
}

/// `InitiateMultipartUploadResult` body.
pub fn initiate_multipart_xml(bucket: &str, key: &str, upload_id: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId></InitiateMultipartUploadResult>"#,
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(upload_id)
    )
}

/// `CompleteMultipartUploadResult` body.
pub fn complete_multipart_xml(bucket: &str, key: &str, etag: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Location>/{}/{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag></CompleteMultipartUploadResult>"#,
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(etag)
    )
}

/// `ListPartsResult` body.
pub fn list_parts_xml(bucket: &str, key: &str, upload_id: &str, parts: &[(i32, String, u64)]) -> String {
    let mut body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId><IsTruncated>false</IsTruncated>"#,
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(upload_id)
    );
    for (n, etag, size) in parts {
        body.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag><Size>{}</Size></Part>",
            n,
            xml_escape(etag),
            size
        ));
    }
    body.push_str("</ListPartsResult>");
    body
}

/// Parse `CompleteMultipartUpload` XML into `(part_number, etag)` pairs.
pub fn parse_complete_multipart(xml: &str) -> Result<Vec<(i32, String)>, flash_s3_common::FlashError> {
    let mut parts = Vec::new();
    let mut rest = xml;
    while let Some(block) = extract_block(rest, "Part") {
        let pn: i32 = extract_tag(&block, "PartNumber")
            .and_then(|s| s.parse().ok())
            .ok_or(flash_s3_common::FlashError::InvalidRequest("bad part".into()))?;
        let etag = extract_tag(&block, "ETag")
            .ok_or(flash_s3_common::FlashError::InvalidRequest("bad etag".into()))?;
        parts.push((pn, etag));
        if let Some(idx) = rest.find("</Part>") {
            rest = &rest[idx + 7..];
        } else {
            break;
        }
    }
    if parts.is_empty() {
        return Err(flash_s3_common::FlashError::InvalidRequest(
            "no parts".into(),
        ));
    }
    Ok(parts)
}

// silence unused warning for GroupUri import usage in string compare
#[allow(dead_code)]
fn _uri() -> &'static str {
    GroupUri::ALL_USERS_URI
}
