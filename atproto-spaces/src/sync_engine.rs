//! Client & AppView ATProto Spaces sync engine (`SpaceSyncEngine`).
//!
//! Enforces strict MAC-before-parse ordering:
//! - Cold-open (`fetch_newest_records_verified`): `listRecords(reverse=true, excludeValues=true)`
//!   followed by `getRecord` with `Atproto-Space-Want-Mac` (`atproto-space-record`), verifying
//!   `Atproto-Space-Mac` BEFORE accepting or deserializing record content.
//! - Incremental (`sync_writer_repo`): `listRepoOps(since)` with `Atproto-Space-Want-Mac`
//!   (`atproto-space-repo`), verifying `Atproto-Space-Mac` FIRST on the head commit BEFORE
//!   applying ops to a staged `LtHash` or inspecting record values; falls back to `getRepo`
//!   `STAR-lite` when `allow_star_recovery` is enabled.

use crate::credential_cache::{parse_xrpc_error, CredentialCache, DelegationMinter};
use crate::did_resolver::SpaceDidResolver;
use crate::kem::encapsulate_p256;
use crate::lthash::{compute_dagcbor_cid, compute_record_element_hash, LtHash};
use crate::mac::{
    format_want_mac_header, verify_commit_mac, verify_record_mac, COMMIT_MAC_TYPE, RECORD_MAC_TYPE,
    SPACE_MAC_HEADER_NAME, SPACE_WANT_MAC_HEADER_NAME,
};
use crate::star::{read_star_metadata, read_star_repo, validate_canonical_dagcbor_record};
use crate::{Result, SpaceUri, SpacesError};
use catbird_atproto::com_atproto::space::get_record::GetRecordOutput;
use catbird_atproto::com_atproto::space::list_records::ListRecordsOutput;
use catbird_atproto::com_atproto::space::list_repo_ops::ListRepoOpsOutput;
use catbird_atproto::com_atproto::space::list_repos::ListReposOutput;
use cid::Cid;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;
use url::Url;

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

#[async_trait::async_trait(?Send)]
pub trait SpaceTransport {
    async fn send_http(
        &self,
        method: Method,
        url: &str,
        headers: &HeaderMap,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse>;
}

#[async_trait::async_trait(?Send)]
impl<T: SpaceTransport + ?Sized> SpaceTransport for Rc<T> {
    async fn send_http(
        &self,
        method: Method,
        url: &str,
        headers: &HeaderMap,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse> {
        (**self).send_http(method, url, headers, body).await
    }
}

#[async_trait::async_trait(?Send)]
impl<T: SpaceTransport + ?Sized> SpaceTransport for Arc<T> {
    async fn send_http(
        &self,
        method: Method,
        url: &str,
        headers: &HeaderMap,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse> {
        (**self).send_http(method, url, headers, body).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    Incremental,
    StarRecovery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterSyncState {
    pub latest_rev: Option<String>,
    pub lt_hash: LtHash,
    pub cid_by_path: BTreeMap<String, Cid>,
}

impl Default for WriterSyncState {
    fn default() -> Self {
        Self::empty()
    }
}

impl WriterSyncState {
    pub fn empty() -> Self {
        Self {
            latest_rev: None,
            lt_hash: LtHash::empty(),
            cid_by_path: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSpaceRecord {
    pub uri: String,
    pub collection: String,
    pub rkey: String,
    pub cid: Cid,
    pub record_dagcbor: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoCursorEntry {
    pub did: String,
    pub repo_rev: String,
    pub space_rev: String,
    pub data: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    pub mode: SyncMode,
    pub latest_rev: String,
    pub commitment: [u8; 32],
    pub upserts: Vec<VerifiedSpaceRecord>,
    pub deletes: Vec<(String, String)>,
}

pub struct SpaceSyncEngine<T, R, M> {
    transport: T,
    did_resolver: R,
    credential_cache: CredentialCacheRef<T, R, M>,
}

pub enum CredentialCacheRef<T, R, M> {
    Owned(CredentialCache<T, R, M>),
    Rc(Rc<CredentialCache<T, R, M>>),
    Arc(Arc<CredentialCache<T, R, M>>),
}

impl<T, R, M> CredentialCacheRef<T, R, M> {
    fn as_ref(&self) -> &CredentialCache<T, R, M> {
        match self {
            Self::Owned(c) => c,
            Self::Rc(c) => c,
            Self::Arc(c) => c,
        }
    }
}

impl<T, R, M> From<CredentialCache<T, R, M>> for CredentialCacheRef<T, R, M> {
    fn from(v: CredentialCache<T, R, M>) -> Self {
        Self::Owned(v)
    }
}

impl<T, R, M> From<Rc<CredentialCache<T, R, M>>> for CredentialCacheRef<T, R, M> {
    fn from(v: Rc<CredentialCache<T, R, M>>) -> Self {
        Self::Rc(v)
    }
}

impl<T, R, M> From<Arc<CredentialCache<T, R, M>>> for CredentialCacheRef<T, R, M> {
    fn from(v: Arc<CredentialCache<T, R, M>>) -> Self {
        Self::Arc(v)
    }
}

impl<T, R, M> SpaceSyncEngine<T, R, M>
where
    T: SpaceTransport,
    R: SpaceDidResolver,
    M: DelegationMinter,
{
    pub fn new(
        transport: T,
        did_resolver: R,
        credential_cache: impl Into<CredentialCacheRef<T, R, M>>,
    ) -> Self {
        Self {
            transport,
            did_resolver,
            credential_cache: credential_cache.into(),
        }
    }

    /// List active writer repos in `space_uri` in ascending `spaceRev` order.
    pub async fn list_repos(
        &self,
        space_uri: &str,
        cursor: Option<&str>,
        limit: Option<u32>,
        now_sec: u64,
    ) -> Result<Vec<RepoCursorEntry>> {
        let space = SpaceUri::parse(space_uri)?;
        let authority_doc = self
            .did_resolver
            .resolve_did(&space.authority, false)
            .await?;
        let host_endpoint = authority_doc.space_host_endpoint()?.to_string();

        let mut url = Url::parse(&format!("{host_endpoint}/xrpc/com.atproto.space.listRepos"))
            .map_err(|e| SpacesError::Sync(format!("bad listRepos URL: {e}")))?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("space", space_uri);
            if let Some(c) = cursor {
                qp.append_pair("cursor", c);
            }
            if let Some(l) = limit {
                qp.append_pair("limit", &l.to_string());
            }
        }

        let resp = self
            .send_authenticated_get(space_uri, &space.authority, url.as_str(), None, now_sec)
            .await?;
        let out: ListReposOutput = serde_json::from_slice(&resp.body)
            .map_err(|e| SpacesError::Sync(format!("decode listRepos: {e}")))?;

        let mut entries = Vec::with_capacity(out.repos.len());
        for repo in out.repos {
            let data: [u8; 32] =
                repo.data.as_ref().try_into().map_err(|_| {
                    SpacesError::Sync("listRepos entry data must be 32 bytes".into())
                })?;
            entries.push(RepoCursorEntry {
                did: repo.did.as_str().to_string(),
                repo_rev: repo.repo_rev.as_str().to_string(),
                space_rev: repo.space_rev.as_str().to_string(),
                data,
            });
        }
        Ok(entries)
    }

    /// Cold-open newest records in `collection` from `writer_did`:
    /// 1. `listRecords(reverse=true, excludeValues=true)`
    /// 2. `getRecord` per item with `Atproto-Space-Want-Mac` (`atproto-space-record`)
    /// 3. Verifies `Atproto-Space-Mac` BEFORE accepting or deserializing record payload!
    pub async fn fetch_newest_records_verified(
        &self,
        space_uri: &str,
        writer_did: &str,
        collection: &str,
        limit: u32,
        now_sec: u64,
    ) -> Result<Vec<VerifiedSpaceRecord>> {
        let space = SpaceUri::parse(space_uri)?;
        let writer_doc = self.did_resolver.resolve_did(writer_did, false).await?;
        let pds_endpoint = writer_doc.pds_endpoint()?.to_string();
        let kem_did_key = writer_doc.atproto_kem_did_key.ok_or_else(|| {
            SpacesError::Kem(format!("writer DID {writer_did} has no #atproto_kem key"))
        })?;

        let mut list_url = Url::parse(&format!(
            "{pds_endpoint}/xrpc/com.atproto.space.listRecords"
        ))
        .map_err(|e| SpacesError::Sync(format!("bad listRecords URL: {e}")))?;
        {
            let mut qp = list_url.query_pairs_mut();
            qp.append_pair("space", space_uri);
            qp.append_pair("repo", writer_did);
            qp.append_pair("collection", collection);
            qp.append_pair("limit", &limit.to_string());
            qp.append_pair("reverse", "true");
            qp.append_pair("excludeValues", "true");
        }

        let list_resp = self
            .send_authenticated_get(space_uri, writer_did, list_url.as_str(), None, now_sec)
            .await?;
        let listed: ListRecordsOutput = serde_json::from_slice(&list_resp.body)
            .map_err(|e| SpacesError::Sync(format!("decode listRecords: {e}")))?;

        let mut verified_records = Vec::with_capacity(listed.records.len());
        for stub in listed.records {
            let rkey = stub.rkey.as_ref().to_string();
            let encap = encapsulate_p256(&kem_did_key)?;
            let want_mac = format_want_mac_header(&encap.key_share_did_key, RECORD_MAC_TYPE)?;

            let mut get_url =
                Url::parse(&format!("{pds_endpoint}/xrpc/com.atproto.space.getRecord"))
                    .map_err(|e| SpacesError::Sync(format!("bad getRecord URL: {e}")))?;
            {
                let mut qp = get_url.query_pairs_mut();
                qp.append_pair("space", space_uri);
                qp.append_pair("repo", writer_did);
                qp.append_pair("collection", collection);
                qp.append_pair("rkey", &rkey);
            }

            let resp = self
                .send_authenticated_get(
                    space_uri,
                    writer_did,
                    get_url.as_str(),
                    Some(&want_mac),
                    now_sec,
                )
                .await?;

            let mac_header = resp
                .headers
                .get(SPACE_MAC_HEADER_NAME)
                .ok_or_else(|| {
                    SpacesError::MacMismatch("missing Atproto-Space-Mac on getRecord".into())
                })?
                .to_str()
                .map_err(|_| {
                    SpacesError::MacMismatch("non-ASCII Atproto-Space-Mac header".into())
                })?;

            // Parse minimal envelope (uri + cid) to verify Atproto-Space-Mac BEFORE touching value!
            let minimal: MinimalRecordEnvelope = serde_json::from_slice(&resp.body)
                .map_err(|e| SpacesError::Sync(format!("decode getRecord envelope: {e}")))?;
            let claimed_cid: Cid = minimal
                .cid
                .parse()
                .map_err(|e| SpacesError::MacMismatch(format!("invalid record CID: {e}")))?;
            let expected_uri = space.record_uri(writer_did, collection, &rkey)?;
            if minimal.uri != expected_uri {
                return Err(SpacesError::MacMismatch(format!(
                    "getRecord URI {:?} != expected {:?}",
                    minimal.uri, expected_uri
                )));
            }

            // CRITICAL: Verify record MAC BEFORE deserializing or accepting `value`!
            verify_record_mac(
                &encap.shared_secret,
                mac_header,
                &expected_uri,
                &claimed_cid.to_bytes(),
            )?;

            let full: GetRecordOutput = serde_json::from_slice(&resp.body)
                .map_err(|e| SpacesError::Sync(format!("decode getRecord value: {e}")))?;
            let dagcbor = serde_ipld_dagcbor::to_vec(&full.value)
                .map_err(|e| SpacesError::Sync(format!("encode record DAG-CBOR: {e}")))?;
            validate_canonical_dagcbor_record(&dagcbor)?;
            let computed_cid = compute_dagcbor_cid(&dagcbor);
            if computed_cid != claimed_cid {
                return Err(SpacesError::SetHashMismatch(format!(
                    "getRecord value CID {computed_cid} != authenticated CID {claimed_cid}"
                )));
            }

            verified_records.push(VerifiedSpaceRecord {
                uri: expected_uri,
                collection: collection.to_string(),
                rkey,
                cid: computed_cid,
                record_dagcbor: dagcbor,
            });
        }

        Ok(verified_records)
    }

    /// Incrementally sync `writer_did`'s repo in `space_uri` via `listRepoOps`, verifying
    /// `Atproto-Space-Mac` FIRST and checking `LtHash` commitment BEFORE mutating `state`.
    /// When `allow_star_recovery` is `true`, falls back to `recover_writer_repo_via_star` on
    /// `SetHashMismatch` or oplog gap.
    pub async fn sync_writer_repo(
        &self,
        space_uri: &str,
        writer_did: &str,
        state: &mut WriterSyncState,
        allow_star_recovery: bool,
        now_sec: u64,
    ) -> Result<SyncOutcome> {
        match self
            .try_incremental_sync(space_uri, writer_did, state, now_sec)
            .await
        {
            Ok(outcome) => Ok(outcome),
            Err(err)
                if allow_star_recovery
                    && matches!(err, SpacesError::SetHashMismatch(_) | SpacesError::Sync(_)) =>
            {
                self.recover_writer_repo_via_star(space_uri, writer_did, state, now_sec)
                    .await
            }
            Err(err) => Err(err),
        }
    }

    async fn try_incremental_sync(
        &self,
        space_uri: &str,
        writer_did: &str,
        state: &mut WriterSyncState,
        now_sec: u64,
    ) -> Result<SyncOutcome> {
        let space = SpaceUri::parse(space_uri)?;
        let writer_doc = self.did_resolver.resolve_did(writer_did, false).await?;
        let pds_endpoint = writer_doc.pds_endpoint()?.to_string();
        let kem_did_key = writer_doc.atproto_kem_did_key.ok_or_else(|| {
            SpacesError::Kem(format!("writer DID {writer_did} has no #atproto_kem key"))
        })?;

        let mut staged_lt = state.lt_hash.clone();
        let mut staged_cids = state.cid_by_path.clone();
        let mut upserts_by_path: BTreeMap<String, VerifiedSpaceRecord> = BTreeMap::new();
        let mut deletes_by_path: BTreeMap<String, (String, String)> = BTreeMap::new();

        let mut cursor: Option<String> = None;
        let mut page_count = 0usize;

        loop {
            page_count += 1;
            if page_count > 50 {
                return Err(SpacesError::Sync(
                    "listRepoOps pagination exceeded 50 pages".into(),
                ));
            }
            let encap = encapsulate_p256(&kem_did_key)?;
            let want_mac = format_want_mac_header(&encap.key_share_did_key, COMMIT_MAC_TYPE)?;

            let mut url = Url::parse(&format!(
                "{pds_endpoint}/xrpc/com.atproto.space.listRepoOps"
            ))
            .map_err(|e| SpacesError::Sync(format!("bad listRepoOps URL: {e}")))?;
            {
                let mut qp = url.query_pairs_mut();
                qp.append_pair("space", space_uri);
                qp.append_pair("repo", writer_did);
                if let Some(since) = &state.latest_rev {
                    qp.append_pair("since", since);
                }
                if let Some(c) = &cursor {
                    qp.append_pair("cursor", c);
                }
            }

            let resp = self
                .send_authenticated_get(
                    space_uri,
                    writer_did,
                    url.as_str(),
                    Some(&want_mac),
                    now_sec,
                )
                .await?;

            // If this page carries the head commit (cursor is absent), verify Atproto-Space-Mac
            // BEFORE deserializing ops or applying anything to staged_lt!
            let minimal_page: MinimalOpsPage = serde_json::from_slice(&resp.body)
                .map_err(|e| SpacesError::Sync(format!("decode listRepoOps envelope: {e}")))?;

            let verified_head_commit: Option<(String, [u8; 32])> = if let Some(commit) =
                &minimal_page.commit
            {
                let mac_header = resp
                    .headers
                    .get(SPACE_MAC_HEADER_NAME)
                    .ok_or_else(|| {
                        SpacesError::MacMismatch(
                            "missing Atproto-Space-Mac on head listRepoOps page".into(),
                        )
                    })?
                    .to_str()
                    .map_err(|_| SpacesError::MacMismatch("non-ASCII Atproto-Space-Mac".into()))?;
                let data: [u8; 32] =
                    commit.data.as_ref().try_into().map_err(|_| {
                        SpacesError::MacMismatch("commit.data must be 32 bytes".into())
                    })?;
                if commit.space != space_uri || commit.repo != writer_did || commit.ver != 1 {
                    return Err(SpacesError::MacMismatch(
                        "commit space/repo/ver mismatch on listRepoOps".into(),
                    ));
                }
                // CRITICAL: Verify commit MAC BEFORE parsing or applying ops!
                verify_commit_mac(
                    &encap.shared_secret,
                    mac_header,
                    space_uri,
                    writer_did,
                    &commit.rev,
                    &data,
                )?;
                Some((commit.rev.clone(), data))
            } else {
                None
            };

            let out: ListRepoOpsOutput = serde_json::from_slice(&resp.body)
                .map_err(|e| SpacesError::Sync(format!("decode listRepoOps body: {e}")))?;

            for op in out.ops {
                let collection = op.collection.as_str().to_string();
                let rkey = op.rkey.as_ref().to_string();
                let path = format!("{collection}/{rkey}");

                if let Some(prev_cid_str) = &op.prev {
                    let prev_cid: Cid = prev_cid_str.as_str().parse().map_err(|e| {
                        SpacesError::SetHashMismatch(format!("invalid op.prev CID: {e}"))
                    })?;
                    staged_lt.remove(&compute_record_element_hash(&collection, &rkey, &prev_cid));
                    staged_cids.remove(&path);
                }

                if let Some(new_cid_str) = &op.cid {
                    let new_cid: Cid = new_cid_str.as_str().parse().map_err(|e| {
                        SpacesError::SetHashMismatch(format!("invalid op.cid CID: {e}"))
                    })?;
                    if let Some(val) = &op.value {
                        let dagcbor = serde_ipld_dagcbor::to_vec(val).map_err(|e| {
                            SpacesError::Sync(format!("encode op.value DAG-CBOR: {e}"))
                        })?;
                        validate_canonical_dagcbor_record(&dagcbor)?;
                        let computed_cid = compute_dagcbor_cid(&dagcbor);
                        if computed_cid != new_cid {
                            return Err(SpacesError::SetHashMismatch(format!(
                                "tampered op.value for {path}: computed CID {computed_cid} != op.cid {new_cid}"
                            )));
                        }
                        deletes_by_path.remove(&path);
                        upserts_by_path.insert(
                            path.clone(),
                            VerifiedSpaceRecord {
                                uri: space.record_uri(writer_did, &collection, &rkey)?,
                                collection: collection.clone(),
                                rkey: rkey.clone(),
                                cid: computed_cid,
                                record_dagcbor: dagcbor,
                            },
                        );
                    }
                    staged_lt.add(&compute_record_element_hash(&collection, &rkey, &new_cid));
                    staged_cids.insert(path, new_cid);
                } else {
                    upserts_by_path.remove(&path);
                    deletes_by_path.insert(path, (collection, rkey));
                }
            }

            if let Some(next_cursor) = out.cursor {
                cursor = Some(next_cursor.as_str().to_string());
                continue;
            }

            let Some((head_rev, expected_commitment)) = verified_head_commit else {
                return Err(SpacesError::Sync(
                    "final listRepoOps page omitted head commit".into(),
                ));
            };

            let actual_commitment = staged_lt.commitment();
            if actual_commitment != expected_commitment {
                return Err(SpacesError::SetHashMismatch(
                    "staged LtHash commitment does not match authenticated commit.data".into(),
                ));
            }

            // Atomically commit verified state
            state.latest_rev = Some(head_rev.clone());
            state.lt_hash = staged_lt;
            state.cid_by_path = staged_cids;

            return Ok(SyncOutcome {
                mode: SyncMode::Incremental,
                latest_rev: head_rev,
                commitment: actual_commitment,
                upserts: upserts_by_path.into_values().collect(),
                deletes: deletes_by_path.into_values().collect(),
            });
        }
    }

    /// Full repository recovery via `com.atproto.space.getRepo` (`STAR-lite`),
    /// verifying `Atproto-Space-Mac` FIRST and recomputing `LtHash` over all records.
    pub async fn recover_writer_repo_via_star(
        &self,
        space_uri: &str,
        writer_did: &str,
        state: &mut WriterSyncState,
        now_sec: u64,
    ) -> Result<SyncOutcome> {
        let space = SpaceUri::parse(space_uri)?;
        let writer_doc = self.did_resolver.resolve_did(writer_did, false).await?;
        let pds_endpoint = writer_doc.pds_endpoint()?.to_string();
        let kem_did_key = writer_doc.atproto_kem_did_key.ok_or_else(|| {
            SpacesError::Kem(format!("writer DID {writer_did} has no #atproto_kem key"))
        })?;

        let encap = encapsulate_p256(&kem_did_key)?;
        let want_mac = format_want_mac_header(&encap.key_share_did_key, COMMIT_MAC_TYPE)?;

        let mut url = Url::parse(&format!("{pds_endpoint}/xrpc/com.atproto.space.getRepo"))
            .map_err(|e| SpacesError::Sync(format!("bad getRepo URL: {e}")))?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("space", space_uri);
            qp.append_pair("repo", writer_did);
        }

        let resp = self
            .send_authenticated_get(
                space_uri,
                writer_did,
                url.as_str(),
                Some(&want_mac),
                now_sec,
            )
            .await?;

        let mac_header = resp
            .headers
            .get(SPACE_MAC_HEADER_NAME)
            .ok_or_else(|| SpacesError::MacMismatch("missing Atproto-Space-Mac on getRepo".into()))?
            .to_str()
            .map_err(|_| SpacesError::MacMismatch("non-ASCII Atproto-Space-Mac".into()))?;

        let meta = read_star_metadata(&resp.body, space_uri, writer_did)?;
        // Verify commit MAC BEFORE deserializing record frames or mutating state!
        verify_commit_mac(
            &encap.shared_secret,
            mac_header,
            space_uri,
            writer_did,
            &meta.rev,
            &meta.data,
        )?;
        let parsed = read_star_repo(&resp.body, space_uri, writer_did)?;

        let mut rebuilt_lt = LtHash::empty();
        let mut rebuilt_cids = BTreeMap::new();
        let mut upserts = Vec::with_capacity(parsed.records.len());

        for rec in parsed.records {
            rebuilt_lt.add(&compute_record_element_hash(
                &rec.collection,
                &rec.rkey,
                &rec.cid,
            ));
            rebuilt_cids.insert(rec.path.clone(), rec.cid);
            let uri = space.record_uri(writer_did, &rec.collection, &rec.rkey)?;
            upserts.push(VerifiedSpaceRecord {
                uri,
                collection: rec.collection,
                rkey: rec.rkey,
                cid: rec.cid,
                record_dagcbor: rec.record_dagcbor,
            });
        }

        let commitment = rebuilt_lt.commitment();
        if commitment != parsed.data {
            return Err(SpacesError::SetHashMismatch(
                "STAR-lite recomputed LtHash commitment does not match metadata data".into(),
            ));
        }

        let mut deletes = Vec::new();
        for old_path in state.cid_by_path.keys() {
            if !rebuilt_cids.contains_key(old_path) {
                if let Some((col, rk)) = old_path.split_once('/') {
                    deletes.push((col.to_string(), rk.to_string()));
                }
            }
        }

        state.latest_rev = Some(parsed.rev.clone());
        state.lt_hash = rebuilt_lt;
        state.cid_by_path = rebuilt_cids;

        Ok(SyncOutcome {
            mode: SyncMode::StarRecovery,
            latest_rev: parsed.rev,
            commitment,
            upserts,
            deletes,
        })
    }

    async fn send_authenticated_get(
        &self,
        space_uri: &str,
        audience_did: &str,
        url: &str,
        want_mac: Option<&str>,
        now_sec: u64,
    ) -> Result<HttpResponse> {
        for attempt in 0..2 {
            let signed = self
                .credential_cache
                .as_ref()
                .signed_headers_for_request(space_uri, audience_did, now_sec)
                .await?;
            let mut headers = signed.to_header_map()?;
            if let Some(wm) = want_mac {
                headers.insert(
                    HeaderName::from_static(SPACE_WANT_MAC_HEADER_NAME),
                    HeaderValue::from_str(wm)
                        .map_err(|e| SpacesError::MacMismatch(format!("bad Want-Mac: {e}")))?,
                );
            }
            let resp = self
                .transport
                .send_http(Method::GET, url, &headers, None)
                .await?;
            if resp.status == 200 {
                return Ok(resp);
            }
            let err = parse_xrpc_error(resp.status, &resp.body);
            if matches!(err, SpacesError::CredentialRevoked) && attempt == 0 {
                self.credential_cache.as_ref().evict(space_uri);
                continue;
            }
            return Err(err);
        }
        Err(SpacesError::CredentialRevoked)
    }
}

#[derive(serde::Deserialize)]
struct MinimalRecordEnvelope {
    uri: String,
    cid: String,
}

#[derive(serde::Deserialize)]
struct MinimalOpsPage {
    commit: Option<MinimalCommit>,
}

#[derive(serde::Deserialize)]
struct MinimalCommit {
    ver: i64,
    repo: String,
    space: String,
    rev: String,
    #[serde(with = "jacquard_common::serde_bytes_helper")]
    data: jacquard_common::deps::bytes::Bytes,
}
