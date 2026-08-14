//! Minimal hand-rolled S3 XML serializers/parsers for responses we support.
//!
//! Avoiding a heavy schema stack keeps the binary small; parsers are intentionally
//! tolerant rather than fully XSD-compliant.

use flash_s3_common::{AccessControlPolicy, CorsConfiguration, CorsRule, Grantee, GroupUri};

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

/// `ListBucketResult` body (ListObjectsV2).
pub fn list_objects_v2_xml(
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    max_keys: usize,
    truncated: bool,
    contents: &[IndexEntry],
    common_prefixes: &[String],
    next_token: Option<&str>,
    start_after: Option<&str>,
    continuation_token: Option<&str>,
    encoding_type: Option<&str>,
    owner: Option<(&str, &str)>,
) -> String {
    let encode = encoding_type.map(|t| t.eq_ignore_ascii_case("url")).unwrap_or(false);
    let enc = |s: &str| if encode { s3_url_encode(s) } else { s.to_string() };
    let key_count = contents.len() + common_prefixes.len();
    let mut body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>{}</Name><Prefix>{}</Prefix><MaxKeys>{}</MaxKeys><IsTruncated>{}</IsTruncated><KeyCount>{}</KeyCount>"#,
        xml_escape(bucket),
        xml_escape(&enc(prefix)),
        max_keys,
        truncated,
        key_count
    );
    if let Some(d) = delimiter.filter(|d| !d.is_empty()) {
        body.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(&enc(d))));
    }
    if encode {
        body.push_str("<EncodingType>url</EncodingType>");
    }
    if let Some(t) = continuation_token {
        body.push_str(&format!(
            "<ContinuationToken>{}</ContinuationToken>",
            xml_escape(t)
        ));
    }
    if let Some(t) = next_token {
        body.push_str(&format!(
            "<NextContinuationToken>{}</NextContinuationToken>",
            xml_escape(t)
        ));
    }
    if let Some(s) = start_after {
        body.push_str(&format!("<StartAfter>{}</StartAfter>", xml_escape(s)));
    }
    append_contents_and_prefixes(&mut body, contents, common_prefixes, encode, owner);
    body.push_str("</ListBucketResult>");
    body
}

/// `ListBucketResult` body (ListObjects V1).
pub fn list_objects_v1_xml(
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    marker: Option<&str>,
    max_keys: usize,
    truncated: bool,
    contents: &[IndexEntry],
    common_prefixes: &[String],
    next_marker: Option<&str>,
    encoding_type: Option<&str>,
    owner: Option<(&str, &str)>,
) -> String {
    let encode = encoding_type.map(|t| t.eq_ignore_ascii_case("url")).unwrap_or(false);
    let enc = |s: &str| if encode { s3_url_encode(s) } else { s.to_string() };
    let mut body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>{}</Name><Prefix>{}</Prefix><Marker>{}</Marker><MaxKeys>{}</MaxKeys><IsTruncated>{}</IsTruncated>"#,
        xml_escape(bucket),
        xml_escape(&enc(prefix)),
        xml_escape(marker.unwrap_or("")),
        max_keys,
        truncated
    );
    if let Some(d) = delimiter.filter(|d| !d.is_empty()) {
        body.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(&enc(d))));
    }
    if encode {
        body.push_str("<EncodingType>url</EncodingType>");
    }
    if truncated {
        if let Some(m) = next_marker {
            body.push_str(&format!("<NextMarker>{}</NextMarker>", xml_escape(m)));
        }
    }
    append_contents_and_prefixes(&mut body, contents, common_prefixes, encode, owner);
    body.push_str("</ListBucketResult>");
    body
}

/// `ListVersionsResult` for non-versioned buckets (each object as `VersionId=null`).
///
/// Enough for S3 clients / Ceph s3-tests cleanup (`nuke_bucket` uses ListObjectVersions
/// before DeleteBucket). Full versioning is not implemented.
pub fn list_object_versions_xml(
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    key_marker: Option<&str>,
    version_id_marker: Option<&str>,
    max_keys: usize,
    truncated: bool,
    contents: &[IndexEntry],
    common_prefixes: &[String],
    next_key_marker: Option<&str>,
    owner_id: &str,
    owner_name: &str,
) -> String {
    let mut body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>{}</Name><Prefix>{}</Prefix><KeyMarker>{}</KeyMarker><VersionIdMarker>{}</VersionIdMarker><MaxKeys>{}</MaxKeys><IsTruncated>{}</IsTruncated>"#,
        xml_escape(bucket),
        xml_escape(prefix),
        xml_escape(key_marker.unwrap_or("")),
        xml_escape(version_id_marker.unwrap_or("")),
        max_keys,
        truncated
    );
    if let Some(d) = delimiter {
        body.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(d)));
    }
    if truncated {
        if let Some(k) = next_key_marker {
            body.push_str(&format!(
                "<NextKeyMarker>{}</NextKeyMarker><NextVersionIdMarker>null</NextVersionIdMarker>",
                xml_escape(k)
            ));
        }
    }
    for c in contents {
        body.push_str(&format!(
            "<Version><Key>{}</Key><VersionId>null</VersionId><IsLatest>true</IsLatest><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass><Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner></Version>",
            xml_escape(&c.key),
            xml_escape(&c.last_modified),
            xml_escape(&c.etag),
            c.size,
            xml_escape(owner_id),
            xml_escape(owner_name)
        ));
    }
    for p in common_prefixes {
        body.push_str(&format!(
            "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
            xml_escape(p)
        ));
    }
    body.push_str("</ListVersionsResult>");
    body
}

/// URL-encode for `encoding-type=url` (keep `/` unencoded, like AWS S3).
pub fn s3_url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn append_contents_and_prefixes(
    body: &mut String,
    contents: &[IndexEntry],
    common_prefixes: &[String],
    encode: bool,
    owner: Option<(&str, &str)>,
) {
    let enc = |s: &str| if encode { s3_url_encode(s) } else { s.to_string() };
    for c in contents {
        body.push_str(&format!(
            "<Contents><Key>{}</Key><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass>",
            xml_escape(&enc(&c.key)),
            xml_escape(&c.last_modified),
            xml_escape(&c.etag),
            c.size
        ));
        if let Some((oid, oname)) = owner {
            body.push_str(&format!(
                "<Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner>",
                xml_escape(oid),
                xml_escape(oname)
            ));
        }
        body.push_str("</Contents>");
    }
    for p in common_prefixes {
        body.push_str(&format!(
            "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
            xml_escape(&enc(p))
        ));
    }
}

/// Empty `LocationConstraint` XML (`us-east-1`) or region string.
pub fn bucket_location_xml(region: &str) -> String {
    if region == "us-east-1" {
        r#"<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>"#.into()
    } else {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">{}</LocationConstraint>"#,
            xml_escape(region)
        )
    }
}

/// Tagging configuration XML.
pub fn tagging_xml(tags: &[(String, String)]) -> String {
    let mut body = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet>"#,
    );
    for (k, v) in tags {
        body.push_str(&format!(
            "<Tag><Key>{}</Key><Value>{}</Value></Tag>",
            xml_escape(k),
            xml_escape(v)
        ));
    }
    body.push_str("</TagSet></Tagging>");
    body
}

/// Parse `<Tagging><TagSet><Tag><Key/><Value/></Tag>…` XML.
pub fn parse_tagging_xml(raw: &str) -> Result<Vec<(String, String)>, flash_s3_common::FlashError> {
    let mut tags = Vec::new();
    let mut rest = raw;
    while let Some(block) = extract_block(rest, "Tag") {
        let key = extract_tag(&block, "Key").unwrap_or_default();
        let value = extract_tag(&block, "Value").unwrap_or_default();
        if key.is_empty() {
            return Err(flash_s3_common::FlashError::InvalidRequest(
                "tag key required".into(),
            ));
        }
        tags.push((key, value));
        if let Some(idx) = rest.find("</Tag>") {
            rest = &rest[idx + "</Tag>".len()..];
        } else {
            break;
        }
    }
    if tags.len() > 50 {
        return Err(flash_s3_common::FlashError::InvalidRequest(
            "too many tags".into(),
        ));
    }
    Ok(tags)
}

/// Parse multi-object delete request.
pub fn parse_delete_objects_xml(
    raw: &str,
) -> Result<(bool, Vec<String>), flash_s3_common::FlashError> {
    let quiet = extract_tag(raw, "Quiet")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut keys = Vec::new();
    let mut rest = raw;
    while let Some(block) = extract_block(rest, "Object") {
        let key = extract_tag(&block, "Key").unwrap_or_default();
        if key.is_empty() {
            return Err(flash_s3_common::FlashError::InvalidRequest(
                "Delete Object Key required".into(),
            ));
        }
        keys.push(key);
        if let Some(idx) = rest.find("</Object>") {
            rest = &rest[idx + "</Object>".len()..];
        } else {
            break;
        }
    }
    Ok((quiet, keys))
}

/// Multi-object delete result XML.
pub fn delete_objects_result_xml(
    deleted: &[String],
    errors: &[(String, &str, &str)],
) -> String {
    let mut body = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    for key in deleted {
        body.push_str(&format!("<Deleted><Key>{}</Key></Deleted>", xml_escape(key)));
    }
    for (key, code, message) in errors {
        body.push_str(&format!(
            "<Error><Key>{}</Key><Code>{}</Code><Message>{}</Message></Error>",
            xml_escape(key),
            xml_escape(code),
            xml_escape(message)
        ));
    }
    body.push_str("</DeleteResult>");
    body
}

/// `ListMultipartUploadsResult` XML.
pub fn list_multipart_uploads_xml(
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    key_marker: Option<&str>,
    upload_id_marker: Option<&str>,
    max_uploads: usize,
    truncated: bool,
    uploads: &[(String, String, String)],
    common_prefixes: &[String],
    next_key_marker: Option<&str>,
    next_upload_id_marker: Option<&str>,
) -> String {
    let mut body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>{}</Bucket><Prefix>{}</Prefix><KeyMarker>{}</KeyMarker><UploadIdMarker>{}</UploadIdMarker><MaxUploads>{}</MaxUploads><IsTruncated>{}</IsTruncated>"#,
        xml_escape(bucket),
        xml_escape(prefix),
        xml_escape(key_marker.unwrap_or("")),
        xml_escape(upload_id_marker.unwrap_or("")),
        max_uploads,
        truncated
    );
    if let Some(d) = delimiter {
        body.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(d)));
    }
    if truncated {
        if let Some(k) = next_key_marker {
            body.push_str(&format!(
                "<NextKeyMarker>{}</NextKeyMarker>",
                xml_escape(k)
            ));
        }
        if let Some(u) = next_upload_id_marker {
            body.push_str(&format!(
                "<NextUploadIdMarker>{}</NextUploadIdMarker>",
                xml_escape(u)
            ));
        }
    }
    for (key, upload_id, initiated) in uploads {
        body.push_str(&format!(
            "<Upload><Key>{}</Key><UploadId>{}</UploadId><Initiated>{}</Initiated><StorageClass>STANDARD</StorageClass></Upload>",
            xml_escape(key),
            xml_escape(upload_id),
            xml_escape(initiated)
        ));
    }
    for p in common_prefixes {
        body.push_str(&format!(
            "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
            xml_escape(p)
        ));
    }
    body.push_str("</ListMultipartUploadsResult>");
    body
}

/// `CopyPartResult` XML for UploadPartCopy.
pub fn copy_part_result_xml(etag: &str, last_modified: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><CopyPartResult><LastModified>{}</LastModified><ETag>{}</ETag></CopyPartResult>"#,
        xml_escape(last_modified),
        xml_escape(etag)
    )
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

/// `CORSConfiguration` XML for GetBucketCors.
pub fn cors_xml(cors: &CorsConfiguration) -> String {
    cors.to_xml()
}

/// Parse `CORSConfiguration` XML for PutBucketCors.
pub fn parse_cors_xml(raw: &str) -> Result<CorsConfiguration, flash_s3_common::FlashError> {
    if !raw.contains("CORSConfiguration") && !raw.contains("CORSRule") {
        return Err(flash_s3_common::FlashError::MalformedCORSConfiguration);
    }
    let mut rules = Vec::new();
    let mut rest = raw;
    while let Some(block) = extract_block(rest, "CORSRule") {
        let id = extract_tag(&block, "ID");
        let allowed_origins = extract_all_tags(&block, "AllowedOrigin");
        let allowed_methods = extract_all_tags(&block, "AllowedMethod");
        let allowed_headers = extract_all_tags(&block, "AllowedHeader");
        let expose_headers = extract_all_tags(&block, "ExposeHeader");
        let max_age_seconds = extract_tag(&block, "MaxAgeSeconds")
            .map(|s| {
                s.parse::<u32>()
                    .map_err(|_| flash_s3_common::FlashError::MalformedCORSConfiguration)
            })
            .transpose()?;
        rules.push(CorsRule {
            id,
            allowed_origins,
            allowed_methods: allowed_methods
                .into_iter()
                .map(|m| m.to_ascii_uppercase())
                .collect(),
            allowed_headers,
            expose_headers,
            max_age_seconds,
        });
        if let Some(idx) = rest.find("</CORSRule>") {
            rest = &rest[idx + "</CORSRule>".len()..];
        } else {
            break;
        }
    }
    let cors = CorsConfiguration { rules };
    cors.validate()?;
    Ok(cors)
}

fn extract_all_tags(xml: &str, tag: &str) -> Vec<String> {
    let mut values = Vec::new();
    let start = format!("<{tag}>");
    let end = format!("</{tag}>");
    let mut rest = xml;
    while let Some(i) = rest.find(&start) {
        let after = i + start.len();
        let Some(rel) = rest[after..].find(&end) else {
            break;
        };
        values.push(rest[after..after + rel].to_string());
        rest = &rest[after + rel + end.len()..];
    }
    values
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

/// `PostResponse` body for `success_action_status` 200/201.
pub fn post_response_xml(location: &str, bucket: &str, key: &str, etag: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><PostResponse><Location>{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag></PostResponse>"#,
        xml_escape(location),
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(etag),
    )
}

// silence unused warning for GroupUri import usage in string compare
#[allow(dead_code)]
fn _uri() -> &'static str {
    GroupUri::ALL_USERS_URI
}
