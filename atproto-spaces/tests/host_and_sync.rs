use atproto_spaces::credential_cache::{CredentialCache, DelegationMinter};
use atproto_spaces::did_resolver::{DidDocument, StaticDidResolver};
use atproto_spaces::host::{InMemorySpaceHostBackend, SpaceHost, SpaceRecordPolicy};
use atproto_spaces::kem::{decapsulate_p256, encode_p256_did_key, P256SecretKey};
use atproto_spaces::lthash::{compute_dagcbor_cid, compute_record_element_hash, LtHash};
use atproto_spaces::mac::{
    parse_accept_signature, sign_commit_mac, sign_record_mac, MacProfile, ACCEPT_SIGNATURE_HEADER,
};
use atproto_spaces::star::{write_star_repo, StarRecordEntry};
use atproto_spaces::sync_engine::{
    HttpResponse, SpaceSyncEngine, SpaceTransport, SyncMode, WriterSyncState, WriterUpdateEntry,
};
use atproto_spaces::tokens::{mint_space_token, SpaceSigningKey, SpaceTokenClaims, SpaceTokenKind};
use atproto_spaces::SpacesError;
use http::{HeaderMap, HeaderValue, Method};
use petrel_api::generated::com::atproto::space::authorize_space_sync::{
    Input as AuthorizeSpaceSync, Notify,
};
use petrel_api::generated::com::atproto::space::confirm_registration::Output as ConfirmRegistrationOutput;
use petrel_api::generated::com::atproto::space::list_writers::Parameters as ListWriters;
use petrel_api::generated::com::atproto::space::notify_repo_update::Input as NotifyRepoUpdate;
use petrel_api::generated::com::atproto::space::notify_space_update::InputUpdate as NotifySpaceUpdateUpdate;
use petrel_api::generated::com::atproto::space::remove_writer::Input as RemoveWriter;
use petrel_core::Bytes;
use petrel_core::SpaceRef;
use petrel_core::{Did, Tid, Uri};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

struct StaticDelegationMinter {
    user_did: String,
    user_signing_key: SpaceSigningKey,
    fixed_jti: Option<String>,
    now_sec: u64,
}

#[async_trait::async_trait(?Send)]
impl DelegationMinter for StaticDelegationMinter {
    async fn mint_delegation_token(
        &self,
        space_uri: &str,
        authority_did: &str,
    ) -> atproto_spaces::Result<String> {
        let jti = self
            .fixed_jti
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let claims = SpaceTokenClaims {
            iss: self.user_did.clone(),
            sub: space_uri.to_string(),
            aud: Some(format!("{authority_did}#atproto_pds")),
            iat: self.now_sec,
            exp: self.now_sec + 60,
            jti,
            cnf_kid: None,
        };
        mint_space_token(SpaceTokenKind::Delegation, &self.user_signing_key, &claims)
    }
}

#[derive(Clone)]
struct StoredRecord {
    collection: String,
    rkey: String,
    _rev: String,
    dagcbor: Vec<u8>,
}

struct MockRepoHost {
    _repo_did: String,
    kem_secret: P256SecretKey,
    records: BTreeMap<String, StoredRecord>, // key: "{collection}/{rkey}"
    oplog: Vec<MockOp>,
    latest_rev: String,
    tamper_next_list_ops_value: bool,
    tamper_next_record_mac: bool,
    omit_next_list_ops_commit: bool,
}

#[derive(Clone)]
struct MockOp {
    rev: String,
    collection: String,
    rkey: String,
    cid: Option<cid::Cid>,
    prev: Option<cid::Cid>,
    dagcbor: Option<Vec<u8>>,
}

impl MockRepoHost {
    fn new(repo_did: &str, kem_secret: P256SecretKey) -> Self {
        Self {
            _repo_did: repo_did.to_string(),
            kem_secret,
            records: BTreeMap::new(),
            oplog: Vec::new(),
            latest_rev: "3l2aaaaaaaaaa".to_string(),
            tamper_next_list_ops_value: false,
            tamper_next_record_mac: false,
            omit_next_list_ops_commit: false,
        }
    }

    fn put_record(
        &mut self,
        collection: &str,
        rkey: &str,
        rev: &str,
        json_val: serde_json::Value,
    ) -> [u8; 32] {
        let dagcbor = serde_ipld_dagcbor::to_vec(&json_val).unwrap();
        let new_cid = compute_dagcbor_cid(&dagcbor);
        let key = format!("{collection}/{rkey}");
        let prev = self
            .records
            .get(&key)
            .map(|old| compute_dagcbor_cid(&old.dagcbor));
        self.records.insert(
            key,
            StoredRecord {
                collection: collection.to_string(),
                rkey: rkey.to_string(),
                _rev: rev.to_string(),
                dagcbor: dagcbor.clone(),
            },
        );
        self.oplog.push(MockOp {
            rev: rev.to_string(),
            collection: collection.to_string(),
            rkey: rkey.to_string(),
            cid: Some(new_cid),
            prev,
            dagcbor: Some(dagcbor),
        });
        self.latest_rev = rev.to_string();
        self.current_commitment()
    }

    fn current_commitment(&self) -> [u8; 32] {
        let mut lt = LtHash::empty();
        for rec in self.records.values() {
            let cid = compute_dagcbor_cid(&rec.dagcbor);
            lt.add(&compute_record_element_hash(
                &rec.collection,
                &rec.rkey,
                &cid,
            ));
        }
        lt.commitment()
    }
}

struct MockNetwork {
    space_host: Rc<SpaceHost<InMemorySpaceHostBackend, Rc<StaticDidResolver>>>,
    repos: Rc<RefCell<BTreeMap<String, MockRepoHost>>>,
    now_sec: u64,
}

#[async_trait::async_trait(?Send)]
impl SpaceTransport for MockNetwork {
    async fn send_http(
        &self,
        method: Method,
        url: &str,
        headers: &HeaderMap,
        body: Option<&[u8]>,
    ) -> atproto_spaces::Result<HttpResponse> {
        let parsed = url::Url::parse(url).unwrap();
        let path = parsed.path();
        let query: BTreeMap<String, String> = parsed.query_pairs().into_owned().collect();

        match (method, path) {
            (Method::POST, "/xrpc/com.atproto.space.authorizeSpaceSync") => {
                let req: AuthorizeSpaceSync =
                    serde_json::from_slice(body.unwrap_or_default()).unwrap();
                match self
                    .space_host
                    .handle_authorize_space_sync(req, self.now_sec)
                    .await
                {
                    Ok(out) => Ok(HttpResponse {
                        status: 200,
                        headers: HeaderMap::new(),
                        body: serde_json::to_vec(&out).unwrap(),
                    }),
                    Err(err) => Ok(error_to_http(err)),
                }
            }
            (Method::GET, "/xrpc/com.atproto.space.listWriters") => {
                let req = ListWriters {
                    space: SpaceRef::parse(query.get("space").unwrap().as_str()).unwrap(),
                    cursor: query.get("cursor").map(|s| s.as_str().into()),
                    limit: query
                        .get("limit")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(100),
                };
                match self
                    .space_host
                    .handle_list_writers(headers, req, self.now_sec)
                    .await
                {
                    Ok(out) => Ok(HttpResponse {
                        status: 200,
                        headers: HeaderMap::new(),
                        body: serde_json::to_vec(&out).unwrap(),
                    }),
                    Err(err) => Ok(error_to_http(err)),
                }
            }
            (Method::GET, "/xrpc/com.atproto.space.listRecords") => {
                let space = query.get("space").unwrap().clone();
                self.space_host
                    .verify_presentation(headers, &space, query.get("repo").unwrap(), self.now_sec)
                    .await?;
                let repo_did = query.get("repo").unwrap();
                let collection_filter = query.get("collection").cloned();
                let reverse = query.get("reverse").map(|v| v == "true").unwrap_or(false);
                let exclude_values = query
                    .get("excludeValues")
                    .map(|v| v == "true")
                    .unwrap_or(false);
                let limit: usize = query
                    .get("limit")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(50);

                let repos = self.repos.borrow();
                let host = repos.get(repo_did).expect("mock repo exists");
                let mut recs: Vec<&StoredRecord> = host
                    .records
                    .values()
                    .filter(|r| {
                        collection_filter
                            .as_ref()
                            .map(|c| c == &r.collection)
                            .unwrap_or(true)
                    })
                    .collect();
                recs.sort_by(|a, b| a.rkey.cmp(&b.rkey));
                if reverse {
                    recs.reverse();
                }
                recs.truncate(limit);

                let items: Vec<serde_json::Value> = recs
                    .into_iter()
                    .map(|r| {
                        let cid = compute_dagcbor_cid(&r.dagcbor);
                        let mut obj = serde_json::json!({
                            "collection": r.collection,
                            "rkey": r.rkey,
                            "cid": cid.to_string(),
                        });
                        if !exclude_values {
                            let val: serde_json::Value =
                                serde_ipld_dagcbor::from_slice(&r.dagcbor).unwrap();
                            obj["value"] = val;
                        }
                        obj
                    })
                    .collect();
                Ok(HttpResponse {
                    status: 200,
                    headers: HeaderMap::new(),
                    body: serde_json::to_vec(&serde_json::json!({ "records": items })).unwrap(),
                })
            }
            (Method::GET, "/xrpc/com.atproto.space.getRecord") => {
                let space = query.get("space").unwrap().clone();
                let repo_did = query.get("repo").unwrap().clone();
                let collection = query.get("collection").unwrap().clone();
                let rkey = query.get("rkey").unwrap().clone();
                self.space_host
                    .verify_presentation(headers, &space, &repo_did, self.now_sec)
                    .await?;

                let accept_sig = headers
                    .get(ACCEPT_SIGNATURE_HEADER)
                    .unwrap()
                    .to_str()
                    .unwrap();
                let (label, key_share) = parse_accept_signature(accept_sig, MacProfile::Record)?;

                let mut repos = self.repos.borrow_mut();
                let host = repos.get_mut(&repo_did).unwrap();
                let rec = host
                    .records
                    .get(&format!("{collection}/{rkey}"))
                    .expect("record exists")
                    .clone();
                let cid = compute_dagcbor_cid(&rec.dagcbor);
                let uri = format!("{space}/{repo_did}/{collection}/{rkey}");
                let mut secret = decapsulate_p256(&host.kem_secret, &key_share)?;
                if host.tamper_next_record_mac {
                    host.tamper_next_record_mac = false;
                    secret[0] ^= 0xff;
                }
                let (mac_headers, _) =
                    sign_record_mac(&secret, &key_share, &label, &uri, &cid.to_string())?;
                let val: serde_json::Value = serde_ipld_dagcbor::from_slice(&rec.dagcbor).unwrap();
                let resp_headers = mac_headers.to_header_map()?;
                Ok(HttpResponse {
                    status: 200,
                    headers: resp_headers,
                    body: serde_json::to_vec(&serde_json::json!({
                        "uri": uri,
                        "cid": cid.to_string(),
                        "value": val,
                    }))
                    .unwrap(),
                })
            }
            (Method::GET, "/xrpc/com.atproto.space.listRepoOps") => {
                let space = query.get("space").unwrap().clone();
                let repo_did = query.get("repo").unwrap().clone();
                let since = query.get("since").cloned();
                self.space_host
                    .verify_presentation(headers, &space, &repo_did, self.now_sec)
                    .await?;

                let accept_sig = headers
                    .get(ACCEPT_SIGNATURE_HEADER)
                    .unwrap()
                    .to_str()
                    .unwrap();
                let (label, key_share) = parse_accept_signature(accept_sig, MacProfile::Commit)?;

                let mut repos = self.repos.borrow_mut();
                let host = repos.get_mut(&repo_did).unwrap();
                let tamper = host.tamper_next_list_ops_value;
                host.tamper_next_list_ops_value = false;
                let omit_commit = host.omit_next_list_ops_commit;
                host.omit_next_list_ops_commit = false;

                let ops_json: Vec<serde_json::Value> = host
                    .oplog
                    .iter()
                    .filter(|op| since.as_ref().map(|s| op.rev > *s).unwrap_or(true))
                    .map(|op| {
                        let mut entry = serde_json::json!({
                            "rev": op.rev,
                            "collection": op.collection,
                            "rkey": op.rkey,
                        });
                        if let Some(cid) = &op.cid {
                            entry["cid"] = serde_json::Value::String(cid.to_string());
                        }
                        if let Some(prev) = &op.prev {
                            entry["prev"] = serde_json::Value::String(prev.to_string());
                        }
                        if let Some(dagcbor) = &op.dagcbor {
                            let mut val: serde_json::Value =
                                serde_ipld_dagcbor::from_slice(dagcbor).unwrap();
                            if tamper {
                                val["seq"] = serde_json::json!(999_999);
                            }
                            entry["value"] = val;
                        }
                        entry
                    })
                    .collect();

                let data = host.current_commitment();
                let secret = decapsulate_p256(&host.kem_secret, &key_share)?;
                let (mac_headers, _) = sign_commit_mac(
                    &secret,
                    &key_share,
                    &label,
                    &space,
                    &repo_did,
                    &host.latest_rev,
                    &data,
                )?;
                let mut resp_headers = mac_headers.to_header_map()?;
                let data_b64 =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data);
                let payload = if omit_commit {
                    resp_headers
                        .insert("content-type", HeaderValue::from_static("application/json"));
                    serde_json::json!({ "ops": ops_json })
                } else {
                    serde_json::json!({
                        "ops": ops_json,
                        "commit": {
                            "$type": "com.atproto.space.defs#commit",
                            "ver": 1,
                            "repo": repo_did,
                            "space": space,
                            "rev": host.latest_rev,
                            "data": { "$bytes": data_b64 },
                        }
                    })
                };
                Ok(HttpResponse {
                    status: 200,
                    headers: resp_headers,
                    body: serde_json::to_vec(&payload).unwrap(),
                })
            }
            (Method::GET, "/xrpc/com.atproto.space.getRepo") => {
                let space = query.get("space").unwrap().clone();
                let repo_did = query.get("repo").unwrap().clone();
                self.space_host
                    .verify_presentation(headers, &space, &repo_did, self.now_sec)
                    .await?;

                let accept_sig = headers
                    .get(ACCEPT_SIGNATURE_HEADER)
                    .unwrap()
                    .to_str()
                    .unwrap();
                let (label, key_share) = parse_accept_signature(accept_sig, MacProfile::Commit)?;

                let repos = self.repos.borrow();
                let host = repos.get(&repo_did).unwrap();
                let data = host.current_commitment();
                let mut entries: Vec<StarRecordEntry> = host
                    .records
                    .iter()
                    .map(|(path, rec)| StarRecordEntry {
                        path: path.clone(),
                        record_dagcbor: rec.dagcbor.clone(),
                    })
                    .collect();
                entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
                let star_bytes =
                    write_star_repo(&space, &repo_did, &host.latest_rev, &data, &entries)?;

                let secret = decapsulate_p256(&host.kem_secret, &key_share)?;
                let (mac_headers, _) = sign_commit_mac(
                    &secret,
                    &key_share,
                    &label,
                    &space,
                    &repo_did,
                    &host.latest_rev,
                    &data,
                )?;
                Ok(HttpResponse {
                    status: 200,
                    headers: mac_headers.to_header_map()?,
                    body: star_bytes,
                })
            }
            (m, p) => panic!("unexpected mock HTTP route: {m} {p}"),
        }
    }
}

fn error_to_http(err: SpacesError) -> HttpResponse {
    let status = match &err {
        SpacesError::SpaceNotFound(_) => 404,
        SpacesError::SpaceDeleted(_) => 410,
        SpacesError::Forbidden(_) => 403,
        SpacesError::CredentialRevoked => 401,
        _ => 400,
    };
    HttpResponse {
        status,
        headers: HeaderMap::new(),
        body: serde_json::to_vec(&serde_json::json!({
            "error": err.atproto_error_name(),
            "message": err.to_string(),
        }))
        .unwrap(),
    }
}

#[test]
fn delegation_replay_and_confirm_registration_enforced_in_authorize_space_sync() {
    pollster_block_on(async {
        let now_sec = 1_762_000_000u64;
        let authority_did = "did:web:mls.catbird.blue";
        let alice_did = "did:plc:alice00000000000000000000";
        let space_uri =
            "at:space/did:web:mls.catbird.blue/blue.catbird.labyrinth.conversation/01980a11";

        let confirm_req = SpaceHost::<InMemorySpaceHostBackend>::build_confirm_registration(
            space_uri,
            "secret-token",
            "challenge-xyz",
        )
        .unwrap();
        SpaceHost::<InMemorySpaceHostBackend>::verify_confirm_registration_response(
            "challenge-xyz",
            &ConfirmRegistrationOutput {
                challenge: confirm_req.challenge,
            },
        )
        .expect("matching challenge verifies");
        assert!(matches!(
            SpaceHost::<InMemorySpaceHostBackend>::verify_confirm_registration_response(
                "challenge-xyz",
                &ConfirmRegistrationOutput {
                    challenge: "wrong".into(),
                },
            ),
            Err(SpacesError::RegistrationNotConfirmed(_))
        ));

        let authority_sk = SpaceSigningKey::random_p256();
        let alice_sk = SpaceSigningKey::random_p256();
        let alice_kem = P256SecretKey::random(&mut rand::rngs::OsRng);

        let did_resolver = StaticDidResolver::new();
        did_resolver.insert(DidDocument::with_keys(
            authority_did,
            authority_sk.verifying_key(),
            None,
            "https://mls.catbird.blue",
        ));
        did_resolver.insert(DidDocument::with_keys(
            alice_did,
            alice_sk.verifying_key(),
            Some(encode_p256_did_key(&alice_kem.public_key())),
            "https://pds-alice.example",
        ));
        let did_resolver = Rc::new(did_resolver);

        let backend = InMemorySpaceHostBackend::new();
        backend.create_space(
            space_uri,
            authority_did,
            SpaceRecordPolicy::Members(vec![alice_did.to_string()]),
        );
        let space_host = Rc::new(SpaceHost::new(
            authority_did.to_string(),
            authority_sk,
            did_resolver,
            backend,
        ));

        let minter = StaticDelegationMinter {
            user_did: alice_did.to_string(),
            user_signing_key: alice_sk,
            fixed_jti: Some("replayed-delegation-jti-001".to_string()),
            now_sec,
        };
        let delegation_jwt = minter
            .mint_delegation_token(space_uri, authority_did)
            .await
            .unwrap();
        let eph = P256SecretKey::random(&mut rand::rngs::OsRng);
        let req = AuthorizeSpaceSync {
            space: SpaceRef::parse(space_uri).unwrap(),
            credential_key: encode_p256_did_key(&eph.public_key()),
            delegation_token: Some(delegation_jwt.as_str().into()),
            client_attestation: None,
            notify: Some(Notify {
                endpoint: Uri::parse("https://syncer.catbird.blue").unwrap(),
                token: "syncer-token-01".into(),
                extra_data: None,
            }),
        };

        let minted = space_host
            .handle_authorize_space_sync(req.clone(), now_sec)
            .await
            .expect("first delegation exchange must succeed");
        assert!(!minted.credential.is_empty());
        assert!(minted.space_rev.is_none());

        let replay_err = space_host
            .handle_authorize_space_sync(req, now_sec + 1)
            .await
            .expect_err("replayed delegation jti must fail");
        assert!(matches!(replay_err, SpacesError::InvalidDelegationToken(_)));
    });
}

#[test]
fn nov12_cold_open_incremental_sync_notify_fanout_writer_removal_and_star_recovery() {
    pollster_block_on(async {
        let now_sec = 1_762_000_000u64;
        let authority_did = "did:web:mls.catbird.blue";
        let alice_did = "did:plc:alice00000000000000000000";
        let bob_did = "did:plc:bob0000000000000000000000";
        let space_uri =
            "at:space/did:web:mls.catbird.blue/blue.catbird.labyrinth.conversation/01980a11";

        let authority_sk = SpaceSigningKey::random_p256();
        let alice_sk = SpaceSigningKey::random_p256();
        let bob_sk = SpaceSigningKey::random_p256();
        let alice_kem = P256SecretKey::random(&mut rand::rngs::OsRng);
        let bob_kem = P256SecretKey::random(&mut rand::rngs::OsRng);

        let did_resolver = StaticDidResolver::new();
        did_resolver.insert(DidDocument::with_keys(
            authority_did,
            authority_sk.verifying_key(),
            None,
            "https://mls.catbird.blue",
        ));
        did_resolver.insert(DidDocument::with_keys(
            alice_did,
            alice_sk.verifying_key(),
            Some(encode_p256_did_key(&alice_kem.public_key())),
            "https://pds-alice.example",
        ));
        did_resolver.insert(DidDocument::with_keys(
            bob_did,
            bob_sk.verifying_key(),
            Some(encode_p256_did_key(&bob_kem.public_key())),
            "https://pds-bob.example",
        ));
        let did_resolver = Rc::new(did_resolver);

        let backend = InMemorySpaceHostBackend::new();
        backend.create_space(
            space_uri,
            authority_did,
            SpaceRecordPolicy::Members(vec![alice_did.to_string(), bob_did.to_string()]),
        );
        let space_host = Rc::new(SpaceHost::new(
            authority_did.to_string(),
            authority_sk,
            did_resolver.clone(),
            backend,
        ));

        let mut alice_repo = MockRepoHost::new(alice_did, alice_kem);
        let commit_1 = alice_repo.put_record(
            "blue.catbird.labyrinth.batch",
            "3l2aaaaaaaaab",
            "3l2aaaaaaaaab",
            serde_json::json!({ "$type": "blue.catbird.labyrinth.batch", "seq": 1 }),
        );
        let mut bob_repo = MockRepoHost::new(bob_did, bob_kem);
        let bob_commit_1 = bob_repo.put_record(
            "blue.catbird.labyrinth.batch",
            "3l2aaaaaaaaac",
            "3l2aaaaaaaaac",
            serde_json::json!({ "$type": "blue.catbird.labyrinth.batch", "seq": 1 }),
        );

        let mut repo_map = BTreeMap::new();
        repo_map.insert(alice_did.to_string(), alice_repo);
        repo_map.insert(bob_did.to_string(), bob_repo);
        let repos = Rc::new(RefCell::new(repo_map));

        let network = Rc::new(MockNetwork {
            space_host: space_host.clone(),
            repos: repos.clone(),
            now_sec,
        });

        let bob_minter = Rc::new(StaticDelegationMinter {
            user_did: bob_did.to_string(),
            user_signing_key: bob_sk,
            fixed_jti: None,
            now_sec,
        });
        let bob_cred_cache = Rc::new(
            CredentialCache::new(network.clone(), did_resolver.clone(), bob_minter)
                .with_notify("https://syncer.catbird.blue", "bob-notify-token"),
        );
        let sync_engine = SpaceSyncEngine::new(
            network.clone(),
            did_resolver.clone(),
            bob_cred_cache.clone(),
        );

        // Trigger authorizeSpaceSync with inline notify registration before writes
        let (initial_writers, _) = sync_engine
            .list_writers(space_uri, None, Some(100), now_sec)
            .await
            .unwrap();
        assert!(initial_writers.is_empty());

        // Both Alice and Bob notifyRepoUpdate to SpaceHost -> Bob's notify endpoint gets #repoWrite
        let fanout_1 = space_host
            .handle_notify_repo_update(
                alice_did,
                NotifyRepoUpdate {
                    space: SpaceRef::parse(space_uri).unwrap(),
                    repo: Did::parse(String::from(alice_did)).unwrap(),
                    repo_rev: Tid::parse("3l2aaaaaaaaab").unwrap(),
                    data: Bytes(commit_1.to_vec()),
                },
                now_sec,
            )
            .await
            .expect("alice notifyRepoUpdate 1");
        assert_eq!(fanout_1.len(), 1);
        assert_eq!(fanout_1[0].0, "https://syncer.catbird.blue");
        assert_eq!(fanout_1[0].1.token.as_str(), "bob-notify-token");
        assert!(matches!(
            fanout_1[0].1.update,
            NotifySpaceUpdateUpdate::RepoWrite(_)
        ));

        space_host
            .handle_notify_repo_update(
                bob_did,
                NotifyRepoUpdate {
                    space: SpaceRef::parse(space_uri).unwrap(),
                    repo: Did::parse(String::from(bob_did)).unwrap(),
                    repo_rev: Tid::parse("3l2aaaaaaaaac").unwrap(),
                    data: Bytes(bob_commit_1.to_vec()),
                },
                now_sec,
            )
            .await
            .expect("bob notifyRepoUpdate 1");

        // 1. listWriters shows both Alice and Bob in ascending spaceRev order
        let listed = sync_engine
            .list_active_writers(space_uri, None, Some(100), now_sec)
            .await
            .unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].did, alice_did);
        assert_eq!(listed[1].did, bob_did);

        // 2. Cold-open newest record from Alice with structured record MAC check
        let cold_records = sync_engine
            .fetch_newest_records_verified(
                space_uri,
                alice_did,
                "blue.catbird.labyrinth.batch",
                10,
                now_sec,
            )
            .await
            .expect("cold open verified");
        assert_eq!(cold_records.len(), 1);
        assert_eq!(cold_records[0].rkey, "3l2aaaaaaaaab");

        // Tampering record MAC on getRecord MUST fail with MacMismatch BEFORE returning data
        repos
            .borrow_mut()
            .get_mut(alice_did)
            .unwrap()
            .tamper_next_record_mac = true;
        let bad_mac = sync_engine
            .fetch_newest_records_verified(
                space_uri,
                alice_did,
                "blue.catbird.labyrinth.batch",
                10,
                now_sec,
            )
            .await
            .expect_err("tampered record MAC must be rejected");
        assert!(matches!(bad_mac, SpacesError::MacMismatch(_)));

        // Omitting commit on listRepoOps MUST fail closed with MacMismatch!
        repos
            .borrow_mut()
            .get_mut(alice_did)
            .unwrap()
            .omit_next_list_ops_commit = true;
        let mut alice_state = WriterSyncState::empty();
        assert!(matches!(
            sync_engine
                .sync_writer_repo(space_uri, alice_did, &mut alice_state, false, now_sec)
                .await,
            Err(SpacesError::MacMismatch(_))
        ));

        // 3. Initial sync_writer_repo via listRepoOps
        let sync_1 = sync_engine
            .sync_writer_repo(space_uri, alice_did, &mut alice_state, false, now_sec)
            .await
            .expect("initial incremental sync");
        assert_eq!(sync_1.mode, SyncMode::Incremental);
        assert_eq!(sync_1.latest_rev, "3l2aaaaaaaaab");
        assert_eq!(sync_1.upserts.len(), 1);
        assert_eq!(alice_state.lt_hash.commitment(), commit_1);

        // Alice writes a second batch record
        let commit_2 = repos.borrow_mut().get_mut(alice_did).unwrap().put_record(
            "blue.catbird.labyrinth.batch",
            "3l2aaaaaaaaaf",
            "3l2aaaaaaaaaf",
            serde_json::json!({ "$type": "blue.catbird.labyrinth.batch", "seq": 2 }),
        );

        // Tamper next listRepoOps value: fails with SetHashMismatch when allow_star_recovery = false
        repos
            .borrow_mut()
            .get_mut(alice_did)
            .unwrap()
            .tamper_next_list_ops_value = true;
        let tamper_err = sync_engine
            .sync_writer_repo(space_uri, alice_did, &mut alice_state, false, now_sec)
            .await
            .expect_err("tampered record value must fail");
        assert!(matches!(tamper_err, SpacesError::SetHashMismatch(_)));
        assert_eq!(alice_state.latest_rev.as_deref(), Some("3l2aaaaaaaaab"));

        // With allow_star_recovery = true, tampered listRepoOps automatically recovers via getRepo STAR v0.2!
        repos
            .borrow_mut()
            .get_mut(alice_did)
            .unwrap()
            .tamper_next_list_ops_value = true;
        let recovered = sync_engine
            .sync_writer_repo(space_uri, alice_did, &mut alice_state, true, now_sec)
            .await
            .expect("STAR v0.2 fallback recovery must succeed");
        assert_eq!(recovered.mode, SyncMode::StarRecovery);
        assert_eq!(recovered.latest_rev, "3l2aaaaaaaaaf");
        assert_eq!(recovered.upserts.len(), 2);
        assert_eq!(alice_state.lt_hash.commitment(), commit_2);

        // 4. Removing Bob's writer repo emits #repoRemoved in both notifySpaceUpdate and listWriters,
        // and revoke_user_credentials_and_build_notice emits NotifyCredentialsRevoked!
        let (revocation, writer_targets) = space_host
            .revoke_user_credentials_and_build_notice(space_uri, bob_did, now_sec)
            .expect("build revocation notice");
        assert_eq!(revocation.credentials.len(), 1);
        assert_eq!(
            writer_targets,
            vec![alice_did.to_string(), bob_did.to_string()]
        );

        let remove_fanout = space_host
            .handle_remove_writer(
                authority_did,
                RemoveWriter {
                    space: SpaceRef::parse(space_uri).unwrap(),
                    repo: Did::parse(String::from(bob_did)).unwrap(),
                },
                now_sec,
            )
            .await
            .expect("removeWriter");
        assert!(matches!(
            remove_fanout[0].1.update,
            NotifySpaceUpdateUpdate::RepoRemoved(_)
        ));

        // Bob's cached credential was revoked -> CredentialCache evicts on 401 and mints fresh credential
        // (since Bob is still in InMemorySpaceHostBackend.members until remove_member is called), allowing
        // us to inspect listWriters's #repoRemoved tombstone!
        let (all_events, _) = sync_engine
            .list_writers(space_uri, None, Some(100), now_sec)
            .await
            .unwrap();
        assert_eq!(all_events.len(), 2);
        assert!(matches!(all_events[0], WriterUpdateEntry::Write(_)));
        assert!(matches!(
            &all_events[1],
            WriterUpdateEntry::Removed { did, .. } if did == bob_did
        ));
    });
}

fn pollster_block_on<F: std::future::Future>(mut fut: F) -> F::Output {
    use std::pin::Pin;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn dummy_raw_waker() -> RawWaker {
        fn no_op(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            dummy_raw_waker()
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    let waker = unsafe { Waker::from_raw(dummy_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
        std::thread::yield_now();
    }
}
