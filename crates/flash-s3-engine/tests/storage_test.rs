//! Disk store + listing index integration tests.

use std::io::SeekFrom;

use bytes::Bytes;
use flash_s3_common::{
    AccessControlPolicy, CannedAcl, CanonicalUserId, FlashError, ObjectKey,
};
use flash_s3_engine::metrics::Metrics;
use flash_s3_engine::storage::{layout, ObjectStore, PutObjectOpts};
use futures::future::join_all;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

fn opts(owner: &CanonicalUserId) -> PutObjectOpts {
    PutObjectOpts {
        content_type: Some("text/plain".into()),
        canned_acl: Some(CannedAcl::Private),
        acl: None,
        owner: owner.clone(),
        owner_display_name: "root".into(),
        default_object_acl: CannedAcl::Private,
        user_meta: Default::default(),
        content_encoding: None,
        cache_control: None,
        content_disposition: None,
        content_language: None,
        expires: None,
        checksums: Default::default(),
    }
}

#[tokio::test]
async fn create_put_get_delete_object() {
    let tmp = tempfile::tempdir().unwrap();
    let metrics = Metrics::new().unwrap();
    let store = ObjectStore::open(tmp.path().to_path_buf(), metrics).unwrap();
    let owner = CanonicalUserId::new("o1");

    store
        .create_bucket("demo", owner.clone(), "root", CannedAcl::Private)
        .await
        .unwrap();

    let key = ObjectKey::new("a/b.txt").unwrap();
    let body = Bytes::from_static(b"hello-store");
    let meta = store
        .put_object("demo", &key, body.clone(), opts(&owner))
        .await
        .unwrap();
    assert_eq!(meta.size, body.len() as u64);

    let (got_meta, got) = store.read_object_bytes("demo", &key).await.unwrap();
    assert_eq!(got, body);
    assert_eq!(got_meta.etag, meta.etag);

    let (entries, truncated) = store.list_objects("demo", "a/", None, 100).unwrap();
    assert!(!truncated);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key, "a/b.txt");

    // 4-hex shard path exists
    let h = layout::object_hash_hex("a/b.txt");
    assert!(tmp
        .path()
        .join("buckets/demo/objects")
        .join(&h[0..2])
        .join(&h[2..4])
        .join(&h)
        .join("current/data")
        .exists());

    store.delete_object("demo", &key).await.unwrap();
    assert!(matches!(
        store.get_object_meta("demo", &key).await,
        Err(FlashError::NoSuchKey)
    ));
}

#[tokio::test]
async fn delete_nonempty_bucket_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ObjectStore::open(tmp.path().to_path_buf(), Metrics::new().unwrap()).unwrap();
    let owner = CanonicalUserId::new("o1");
    store
        .create_bucket("full", owner.clone(), "root", CannedAcl::Private)
        .await
        .unwrap();
    let key = ObjectKey::new("x").unwrap();
    store
        .put_object("full", &key, Bytes::from_static(b"1"), opts(&owner))
        .await
        .unwrap();
    assert!(matches!(
        store.delete_bucket("full").await,
        Err(FlashError::BucketNotEmpty)
    ));
}

#[tokio::test]
async fn multipart_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ObjectStore::open(tmp.path().to_path_buf(), Metrics::new().unwrap()).unwrap();
    let owner = CanonicalUserId::new("o1");
    store
        .create_bucket("mparts", owner.clone(), "root", CannedAcl::Private)
        .await
        .unwrap();
    let key = ObjectKey::new("big.bin").unwrap();
    let upload_id = store
        .create_multipart("mparts", &key, owner, "root", None, Some(CannedAcl::Private))
        .await
        .unwrap();

    let p1 = Bytes::from(vec![1u8; 5 * 1024 * 1024]);
    let p2 = Bytes::from(vec![2u8; 1024]);
    let e1 = store.upload_part("mparts", &upload_id, 1, p1.clone()).await.unwrap();
    let e2 = store.upload_part("mparts", &upload_id, 2, p2.clone()).await.unwrap();

    let meta = store
        .complete_multipart(
            "mparts",
            &upload_id,
            &[(1, e1), (2, e2)],
            CannedAcl::Private,
        )
        .await
        .unwrap();
    assert_eq!(meta.size, p1.len() as u64 + p2.len() as u64);

    let (_, data) = store.read_object_bytes("mparts", &key).await.unwrap();
    assert_eq!(&data[..p1.len()], &p1[..]);
    assert_eq!(&data[p1.len()..], &p2[..]);
}

#[tokio::test]
async fn multipart_parallel_parts_preserve_complete_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ObjectStore::open(tmp.path().to_path_buf(), Metrics::new().unwrap()).unwrap();
    let owner = CanonicalUserId::new("o1");
    store
        .create_bucket("parallel", owner.clone(), "root", CannedAcl::Private)
        .await
        .unwrap();

    let key = ObjectKey::new("parallel.bin").unwrap();
    let upload_id = store
        .create_multipart(
            "parallel",
            &key,
            owner,
            "root",
            None,
            Some(CannedAcl::Private),
        )
        .await
        .unwrap();
    let part_count = 4;
    let part_size = 5 * 1024 * 1024;

    let uploads = (1..=part_count).map(|part_number| {
        let store = store.clone();
        let upload_id = upload_id.clone();
        async move {
            let body = Bytes::from(vec![part_number as u8; part_size]);
            let etag = store
                .upload_part("parallel", &upload_id, part_number, body.clone())
                .await
                .unwrap();
            (part_number, etag, body)
        }
    });
    let mut uploaded_parts = join_all(uploads).await;
    uploaded_parts.sort_by_key(|(part_number, _, _)| *part_number);

    let complete_parts = uploaded_parts
        .iter()
        .map(|(part_number, etag, _)| (*part_number, etag.clone()))
        .collect::<Vec<_>>();
    let expected = uploaded_parts
        .iter()
        .flat_map(|(_, _, body)| body.iter().copied())
        .collect::<Vec<_>>();

    let meta = store
        .complete_multipart(
            "parallel",
            &upload_id,
            &complete_parts,
            CannedAcl::Private,
        )
        .await
        .unwrap();
    assert_eq!(meta.size, expected.len() as u64);

    let (_, data) = store.read_object_bytes("parallel", &key).await.unwrap();
    assert_eq!(data.as_ref(), expected.as_slice());
}

#[tokio::test]
#[ignore = "writes and assembles 5 GiB; run explicitly with --ignored"]
async fn multipart_parallel_five_gib_upload() {
    const PART_SIZE: usize = 5 * 1024 * 1024;
    const PART_COUNT: i32 = 1024;
    const CONCURRENCY: i32 = 10;
    const TOTAL_SIZE: u64 = PART_SIZE as u64 * PART_COUNT as u64;

    let tmp = tempfile::tempdir().unwrap();
    let store = ObjectStore::open(tmp.path().to_path_buf(), Metrics::new().unwrap()).unwrap();
    let owner = CanonicalUserId::new("o1");
    store
        .create_bucket("fivegib", owner.clone(), "root", CannedAcl::Private)
        .await
        .unwrap();

    let key = ObjectKey::new("five-gib.bin").unwrap();
    let upload_id = store
        .create_multipart(
            "fivegib",
            &key,
            owner,
            "root",
            None,
            Some(CannedAcl::Private),
        )
        .await
        .unwrap();

    let mut complete_parts = Vec::with_capacity(PART_COUNT as usize);
    for first_part in (1..=PART_COUNT).step_by(CONCURRENCY as usize) {
        let last_part = (first_part + CONCURRENCY - 1).min(PART_COUNT);
        let uploads = (first_part..=last_part).map(|part_number| {
            let store = store.clone();
            let upload_id = upload_id.clone();
            async move {
                let marker = ((part_number - 1) % 251 + 1) as u8;
                let body = Bytes::from(vec![marker; PART_SIZE]);
                let etag = store
                    .upload_part("fivegib", &upload_id, part_number, body)
                    .await
                    .unwrap();
                (part_number, etag)
            }
        });
        complete_parts.extend(join_all(uploads).await);
    }
    complete_parts.sort_by_key(|(part_number, _)| *part_number);

    let meta = store
        .complete_multipart("fivegib", &upload_id, &complete_parts, CannedAcl::Private)
        .await
        .unwrap();
    assert_eq!(meta.size, TOTAL_SIZE);

    let mut object = tokio::fs::File::open(layout::data_path(store.data_dir(), "fivegib", key.as_str()))
        .await
        .unwrap();
    let mut first = [0u8; 1];
    object.read_exact(&mut first).await.unwrap();
    assert_eq!(first[0], 1);

    object
        .seek(SeekFrom::Start(TOTAL_SIZE - 1))
        .await
        .unwrap();
    let mut last = [0u8; 1];
    object.read_exact(&mut last).await.unwrap();
    assert_eq!(last[0], ((PART_COUNT - 1) % 251 + 1) as u8);
}

#[tokio::test]
async fn copy_object() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ObjectStore::open(tmp.path().to_path_buf(), Metrics::new().unwrap()).unwrap();
    let owner = CanonicalUserId::new("o1");
    store
        .create_bucket("copy", owner.clone(), "root", CannedAcl::Private)
        .await
        .unwrap();
    let src = ObjectKey::new("src").unwrap();
    let dst = ObjectKey::new("dst").unwrap();
    store
        .put_object("copy", &src, Bytes::from_static(b"copy-me"), opts(&owner))
        .await
        .unwrap();
    store
        .copy_object("copy", &src, "copy", &dst, opts(&owner))
        .await
        .unwrap();
    let (_, data) = store.read_object_bytes("copy", &dst).await.unwrap();
    assert_eq!(data.as_ref(), b"copy-me");
}

#[tokio::test]
async fn object_acl_persist() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ObjectStore::open(tmp.path().to_path_buf(), Metrics::new().unwrap()).unwrap();
    let owner = CanonicalUserId::new("o1");
    store
        .create_bucket("acl", owner.clone(), "root", CannedAcl::Private)
        .await
        .unwrap();
    let key = ObjectKey::new("pub.txt").unwrap();
    store
        .put_object("acl", &key, Bytes::from_static(b"x"), opts(&owner))
        .await
        .unwrap();
    let public = AccessControlPolicy::from_canned(owner, "root", CannedAcl::PublicRead);
    store.put_object_acl("acl", &key, public.clone()).await.unwrap();
    let meta = store.get_object_meta("acl", &key).await.unwrap();
    assert!(meta.acl.allows(None, flash_s3_common::Permission::Read, false));
}

#[tokio::test]
async fn bucket_policy_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ObjectStore::open(tmp.path().to_path_buf(), Metrics::new().unwrap()).unwrap();
    let owner = CanonicalUserId::new("o1");
    store
        .create_bucket("pol", owner, "root", CannedAcl::Private)
        .await
        .unwrap();
    let raw = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pol/*"}]}"#;
    store.put_bucket_policy("pol", raw).await.unwrap();
    assert_eq!(store.get_bucket_policy("pol").await.unwrap(), raw);
    let parsed = store.load_policy("pol").await.unwrap().unwrap();
    assert_eq!(
        parsed.evaluate("s3:GetObject", "arn:aws:s3:::pol/k", None),
        Some(true)
    );
}

#[tokio::test]
async fn bucket_cors_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ObjectStore::open(tmp.path().to_path_buf(), Metrics::new().unwrap()).unwrap();
    let owner = CanonicalUserId::new("o1");
    store
        .create_bucket("cors", owner, "root", CannedAcl::Private)
        .await
        .unwrap();
    let raw = r#"<?xml version="1.0" encoding="UTF-8"?><CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><CORSRule><AllowedOrigin>http://localhost:3001</AllowedOrigin><AllowedMethod>PUT</AllowedMethod><AllowedMethod>GET</AllowedMethod><AllowedHeader>*</AllowedHeader><MaxAgeSeconds>3000</MaxAgeSeconds></CORSRule></CORSConfiguration>"#;
    store.put_bucket_cors("cors", raw).await.unwrap();
    assert_eq!(store.get_bucket_cors("cors").await.unwrap(), raw);
    let loaded = store.load_cors_raw("cors").await.unwrap().unwrap();
    assert!(loaded.contains("localhost:3001"));
    store.delete_bucket_cors("cors").await.unwrap();
    assert!(matches!(
        store.get_bucket_cors("cors").await,
        Err(FlashError::NoSuchCORSConfiguration)
    ));
}
