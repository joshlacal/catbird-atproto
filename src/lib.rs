#![allow(non_snake_case)]

pub mod generated;

pub use generated::blue_catbird;
pub use generated::builder_types;
pub use jacquard_common;
pub use jacquard_common::types;
pub use jacquard_derive;

pub mod catbird {
    pub mod bsky_chat {
        pub mod push_heartbeat {
            pub const NSID: &str = "blue.catbird.bskychat.pushHeartbeat";
        }
        pub mod update_mute_status {
            pub const NSID: &str = "blue.catbird.bskychat.updateMuteStatus";
        }
    }

    pub mod mls_chat {
        pub mod defs {
            pub type ConvoMetadata = crate::blue_catbird::mlsChat::ConvoMetadata<'static>;
            pub type ConvoMetadataData = ConvoMetadata;
            pub type ConvoView = crate::blue_catbird::mlsChat::ConvoView<'static>;
            pub type ConvoViewData = ConvoView;
            pub type MemberView = crate::blue_catbird::mlsChat::MemberView<'static>;
            pub type MemberViewData = MemberView;
            pub type MessageView = crate::blue_catbird::mlsChat::MessageView<'static>;
            pub type MessageViewData = MessageView;
        }

        pub mod send_message {
            pub const NSID: &str = "blue.catbird.mlsChat.sendMessage";

            pub type Input = crate::blue_catbird::mlsChat::send_message::SendMessage<'static>;
            pub type Output =
                crate::blue_catbird::mlsChat::send_message::SendMessageOutput<'static>;

            pub struct InputData {
                pub convo_id: String,
                pub ciphertext: Vec<u8>,
                pub epoch: usize,
                pub msg_id: String,
                pub padded_size: i64,
                pub delivery: Option<String>,
                pub confirmation_tag: Option<String>,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        action: None,
                        ciphertext: bytes::Bytes::from(value.ciphertext),
                        convo_id: value.convo_id.into(),
                        delivery: value.delivery.map(Into::into),
                        extra_data: Default::default(),
                        epoch: value.epoch as i64,
                        msg_id: value.msg_id.into(),
                        padded_size: value.padded_size,
                        reaction_emoji: None,
                        target_message_id: None,
                        confirmation_tag: value.confirmation_tag.map(Into::into),
                    }
                }
            }
        }

        pub mod get_convos {
            pub const NSID: &str = "blue.catbird.mlsChat.getConvos";

            pub type Output = crate::blue_catbird::mlsChat::get_convos::GetConvosOutput<'static>;
        }

        pub mod create_convo {
            pub const NSID: &str = "blue.catbird.mlsChat.createConvo";

            pub type Input = crate::blue_catbird::mlsChat::create_convo::CreateConvo<'static>;
            pub type KeyPackageHashEntry =
                crate::blue_catbird::mlsChat::create_convo::KeyPackageHashEntry<'static>;
            pub type KeyPackageHashEntryData = KeyPackageHashEntry;
            pub type MetadataInput =
                crate::blue_catbird::mlsChat::create_convo::MetadataInput<'static>;
            pub type Output =
                crate::blue_catbird::mlsChat::create_convo::CreateConvoOutput<'static>;

            pub struct MetadataInputData {
                pub description: Option<String>,
                pub name: Option<String>,
            }

            impl From<MetadataInputData> for MetadataInput {
                fn from(value: MetadataInputData) -> Self {
                    Self {
                        description: value.description.map(Into::into),
                        extra_data: Default::default(),
                        name: value.name.map(Into::into),
                    }
                }
            }

            pub struct InputData {
                pub group_id: String,
                pub cipher_suite: String,
                pub initial_members: Option<Vec<crate::types::string::Did<'static>>>,
                pub metadata: Option<MetadataInput>,
                pub welcome_message: Option<String>,
                pub current_epoch: Option<i64>,
                pub key_package_hashes: Option<Vec<KeyPackageHashEntry>>,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        cipher_suite: value.cipher_suite.into(),
                        current_epoch: value.current_epoch,
                        extra_data: Default::default(),
                        group_id: value.group_id.into(),
                        initial_members: value.initial_members,
                        invite: None,
                        key_package_hashes: value.key_package_hashes,
                        metadata: value.metadata,
                        welcome_message: value.welcome_message.map(Into::into),
                    }
                }
            }
        }

        pub mod leave_convo {
            pub const NSID: &str = "blue.catbird.mlsChat.leaveConvo";

            pub type Input = crate::blue_catbird::mlsChat::leave_convo::LeaveConvo<'static>;
            pub type Output = crate::blue_catbird::mlsChat::leave_convo::LeaveConvoOutput<'static>;

            pub struct InputData {
                pub commit: Option<String>,
                pub convo_id: String,
                pub target_did: Option<crate::types::string::Did<'static>>,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        commit: value.commit.map(Into::into),
                        convo_id: value.convo_id.into(),
                        extra_data: Default::default(),
                        target_did: value.target_did,
                    }
                }
            }
        }

        pub mod get_messages {
            pub const NSID: &str = "blue.catbird.mlsChat.getMessages";

            pub type Output =
                crate::blue_catbird::mlsChat::get_messages::GetMessagesOutput<'static>;
        }

        pub mod commit_group_change {
            pub const NSID: &str = "blue.catbird.mlsChat.commitGroupChange";

            pub type Input =
                crate::blue_catbird::mlsChat::commit_group_change::CommitGroupChange<'static>;
            pub type Output =
                crate::blue_catbird::mlsChat::commit_group_change::CommitGroupChangeOutput<'static>;
            pub type KeyPackageHashEntry =
                crate::blue_catbird::mlsChat::commit_group_change::KeyPackageHashEntry<'static>;
            pub type PendingDeviceAddition =
                crate::blue_catbird::mlsChat::commit_group_change::PendingDeviceAddition<'static>;

            pub struct InputData {
                pub action: String,
                pub commit: Option<String>,
                pub confirmation_tag: Option<String>,
                pub convo_id: String,
                pub device_id: Option<String>,
                /// ADR-002 §A7.3: hex-encoded RFC 9420 §8.7 epoch_authenticator
                /// for the post-commit epoch. Optional; server records it when
                /// present on an epoch-advancing action.
                pub epoch_authenticator: Option<String>,
                pub group_info: Option<String>,
                pub idempotency_key: Option<String>,
                pub key_package_hashes: Option<Vec<KeyPackageHashEntry>>,
                pub member_dids: Option<Vec<crate::types::string::Did<'static>>>,
                pub pending_addition_id: Option<String>,
                pub welcome: Option<String>,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        action: value.action.into(),
                        commit: value.commit.map(Into::into),
                        confirmation_tag: value.confirmation_tag.map(Into::into),
                        convo_id: value.convo_id.into(),
                        device_id: value.device_id.map(Into::into),
                        epoch_authenticator: value.epoch_authenticator.map(Into::into),
                        extra_data: Default::default(),
                        group_info: value.group_info.map(Into::into),
                        idempotency_key: value.idempotency_key.map(Into::into),
                        key_package_hashes: value.key_package_hashes,
                        member_dids: value.member_dids,
                        pending_addition_id: value.pending_addition_id.map(Into::into),
                        welcome: value.welcome.map(Into::into),
                    }
                }
            }
        }

        pub mod get_key_packages {
            pub const NSID: &str = "blue.catbird.mlsChat.getKeyPackages";

            pub type Output =
                crate::blue_catbird::mlsChat::get_key_packages::GetKeyPackagesOutput<'static>;
        }

        pub mod get_key_package_status {
            pub const NSID: &str = "blue.catbird.mlsChat.getKeyPackageStatus";

            pub type Input =
                crate::blue_catbird::mlsChat::get_key_package_status::GetKeyPackageStatus<'static>;
            pub type Output =
                crate::blue_catbird::mlsChat::get_key_package_status::GetKeyPackageStatusOutput<
                    'static,
                >;
            pub type Stats =
                crate::blue_catbird::mlsChat::get_key_package_status::KeyPackageStats<'static>;

            pub struct InputData {
                pub cipher_suite: Option<String>,
                pub cursor: Option<String>,
                pub did: Option<crate::types::string::Did<'static>>,
                pub include: Option<String>,
                pub limit: Option<i64>,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        cipher_suite: value.cipher_suite.map(Into::into),
                        cursor: value.cursor.map(Into::into),
                        did: value.did,
                        include: value.include.map(Into::into),
                        limit: value.limit,
                    }
                }
            }
        }

        pub mod get_group_state {
            pub const NSID: &str = "blue.catbird.mlsChat.getGroupState";

            pub type Input = crate::blue_catbird::mlsChat::get_group_state::GetGroupState<'static>;
            pub type Output =
                crate::blue_catbird::mlsChat::get_group_state::GetGroupStateOutput<'static>;

            pub struct InputData {
                pub convo_id: String,
                pub include: Option<String>,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        convo_id: value.convo_id.into(),
                        include: value.include.map(Into::into),
                    }
                }
            }
        }

        pub mod publish_key_packages {
            pub const NSID: &str = "blue.catbird.mlsChat.publishKeyPackages";

            pub type Input =
                crate::blue_catbird::mlsChat::publish_key_packages::PublishKeyPackages<'static>;
            pub type Output =
                crate::blue_catbird::mlsChat::publish_key_packages::PublishKeyPackagesOutput<
                    'static,
                >;
            pub type KeyPackageItem =
                crate::blue_catbird::mlsChat::publish_key_packages::KeyPackageItem<'static>;

            /// Owned, lifetime-free constructor helper for the Jacquard-generated
            /// `KeyPackageItem<'a>`. Exists for four reasons:
            ///
            /// 1. Lifetime erasure — callers build `KeyPackageItem<'static>` without
            ///    threading `'a` through async code and across await points.
            /// 2. Upstream producers give us owned types (`Vec<u8>` from OpenMLS,
            ///    `String` from SQL) rather than `bytes::Bytes`/`CowStr`, so this
            ///    avoids a manual `.into()` + `Bytes::from(...)` dance at every call site.
            /// 3. Defaults Jacquard's `extra_data` passthrough dict so callers can't
            ///    forget it when constructing.
            /// 4. Forward-compat: new lexicon fields won't break call sites that
            ///    construct via `KeyPackageItemData`.
            ///
            /// Note: if the lexicon field type changes (e.g. `bytes` → `string`),
            /// this adapter's `From` impl will fail to compile on regen — that's
            /// the intended tripwire. Fix the lexicon or update the adapter body.
            pub struct KeyPackageItemData {
                pub cipher_suite: String,
                pub expires: crate::types::string::Datetime,
                /// Raw key package bytes (NOT base64 — serde handles encoding)
                pub key_package: Vec<u8>,
            }

            impl From<KeyPackageItemData> for KeyPackageItem {
                fn from(value: KeyPackageItemData) -> Self {
                    Self {
                        cipher_suite: value.cipher_suite.into(),
                        extra_data: Default::default(),
                        expires: value.expires,
                        key_package: bytes::Bytes::from(value.key_package),
                    }
                }
            }

            pub struct InputData {
                pub action: String,
                pub device_id: Option<String>,
                pub key_packages: Option<Vec<KeyPackageItem>>,
                pub local_hashes: Option<Vec<String>>,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        action: value.action.into(),
                        device_id: value.device_id.map(Into::into),
                        extra_data: Default::default(),
                        key_packages: value.key_packages,
                        local_hashes: value
                            .local_hashes
                            .map(|hashes| hashes.into_iter().map(Into::into).collect()),
                    }
                }
            }
        }

        pub mod register_device {
            pub const NSID: &str = "blue.catbird.mlsChat.registerDevice";

            pub type Input = crate::blue_catbird::mlsChat::register_device::RegisterDevice<'static>;
            pub type KeyPackageItem =
                crate::blue_catbird::mlsChat::register_device::KeyPackageItem<'static>;
            pub type Output =
                crate::blue_catbird::mlsChat::register_device::RegisterDeviceOutput<'static>;

            /// Owned-type adapter for `KeyPackageItem<'a>`. See `publish_key_packages::KeyPackageItemData`
            /// for the full rationale — short version: lifetime erasure + owned Vec<u8>/String
            /// + defaults `extra_data` + forward-compat buffer vs lexicon field additions.
            pub struct KeyPackageItemData {
                pub cipher_suite: String,
                pub expires: crate::types::string::Datetime,
                /// Raw key package bytes (NOT base64 — serde handles encoding)
                pub key_package: Vec<u8>,
            }

            impl From<KeyPackageItemData> for KeyPackageItem {
                fn from(value: KeyPackageItemData) -> Self {
                    Self {
                        cipher_suite: value.cipher_suite.into(),
                        extra_data: Default::default(),
                        expires: value.expires,
                        key_package: bytes::Bytes::from(value.key_package),
                    }
                }
            }

            pub struct InputData {
                pub device_uuid: Option<String>,
                pub device_name: String,
                pub signature_public_key: Vec<u8>,
                pub key_packages: Vec<KeyPackageItem>,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        device_name: value.device_name.into(),
                        device_uuid: value.device_uuid.map(Into::into),
                        extra_data: Default::default(),
                        key_packages: value.key_packages,
                        push_token: None,
                        signature_public_key: bytes::Bytes::from(value.signature_public_key),
                    }
                }
            }
        }

        pub mod list_devices {
            pub const NSID: &str = "blue.catbird.mlsChat.listDevices";

            pub type Output =
                crate::blue_catbird::mlsChat::list_devices::ListDevicesOutput<'static>;
        }

        pub mod remove_device {
            pub const NSID: &str = "blue.catbird.mlsChat.removeDevice";

            pub type Input =
                crate::blue_catbird::mlsChat::remove_device::RemoveDevice<'static>;
            pub type Output =
                crate::blue_catbird::mlsChat::remove_device::RemoveDeviceOutput<'static>;

            pub struct InputData {
                pub device_id: String,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        device_id: value.device_id.into(),
                        extra_data: Default::default(),
                    }
                }
            }
        }

        pub mod opt_in {
            pub const NSID: &str = "blue.catbird.mlsChat.optIn";

            pub type Input = crate::blue_catbird::mlsChat::opt_in::OptIn<'static>;
            pub type Output = crate::blue_catbird::mlsChat::opt_in::OptInOutput<'static>;
            pub type Status = crate::blue_catbird::mlsChat::opt_in::OptInStatus<'static>;

            pub struct InputData {
                pub action: String,
                pub allow_followers_bypass: Option<bool>,
                pub allow_following_bypass: Option<bool>,
                pub auto_expire_days: Option<i64>,
                pub device_id: Option<String>,
                pub dids: Option<Vec<crate::types::string::Did<'static>>>,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        action: value.action.into(),
                        allow_followers_bypass: value.allow_followers_bypass,
                        allow_following_bypass: value.allow_following_bypass,
                        auto_expire_days: value.auto_expire_days,
                        device_id: value.device_id.map(Into::into),
                        dids: value.dids,
                        extra_data: Default::default(),
                    }
                }
            }
        }

        pub mod get_opt_in_status {
            pub const NSID: &str = "blue.catbird.mlsChat.optIn";

            pub type Input = crate::blue_catbird::mlsChat::opt_in::OptIn<'static>;
            pub type Output = crate::blue_catbird::mlsChat::opt_in::OptInOutput<'static>;
            pub type Status = crate::blue_catbird::mlsChat::opt_in::OptInStatus<'static>;

            pub struct InputData {
                pub dids: Vec<crate::types::string::Did<'static>>,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        action: "getStatus".into(),
                        allow_followers_bypass: None,
                        allow_following_bypass: None,
                        auto_expire_days: None,
                        device_id: None,
                        dids: Some(value.dids),
                        extra_data: Default::default(),
                    }
                }
            }
        }

        pub mod update_convo {
            pub const NSID: &str = "blue.catbird.mlsChat.updateConvo";

            pub type Input = crate::blue_catbird::mlsChat::update_convo::UpdateConvo<'static>;
            pub type InputData = Input;
            pub type Output =
                crate::blue_catbird::mlsChat::update_convo::UpdateConvoOutput<'static>;
        }

        pub mod promote_admin {
            pub const NSID: &str = "blue.catbird.mlsChat.updateConvo";

            pub type Input = crate::blue_catbird::mlsChat::update_convo::UpdateConvo<'static>;
            pub type Output =
                crate::blue_catbird::mlsChat::update_convo::UpdateConvoOutput<'static>;

            pub struct InputData {
                pub convo_id: String,
                pub target_did: crate::types::string::Did<'static>,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        action: "promoteAdmin".into(),
                        convo_id: value.convo_id.into(),
                        epoch: None,
                        extra_data: Default::default(),
                        group_info: None,
                        policy: None,
                        target_did: Some(value.target_did),
                    }
                }
            }
        }

        pub mod demote_admin {
            pub const NSID: &str = "blue.catbird.mlsChat.updateConvo";

            pub type Input = crate::blue_catbird::mlsChat::update_convo::UpdateConvo<'static>;
            pub type Output =
                crate::blue_catbird::mlsChat::update_convo::UpdateConvoOutput<'static>;

            pub struct InputData {
                pub convo_id: String,
                pub target_did: crate::types::string::Did<'static>,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        action: "demoteAdmin".into(),
                        convo_id: value.convo_id.into(),
                        epoch: None,
                        extra_data: Default::default(),
                        group_info: None,
                        policy: None,
                        target_did: Some(value.target_did),
                    }
                }
            }
        }

        pub mod delete_blob {
            pub const NSID: &str = "blue.catbird.mlsChat.deleteBlob";

            pub type Input = crate::blue_catbird::mlsChat::delete_blob::DeleteBlob<'static>;
            pub type Error = crate::blue_catbird::mlsChat::delete_blob::DeleteBlobError<'static>;
        }

        pub mod get_blob {
            pub const NSID: &str = "blue.catbird.mlsChat.getBlob";

            pub type Input = crate::blue_catbird::mlsChat::get_blob::GetBlob<'static>;
            pub type Output = crate::blue_catbird::mlsChat::get_blob::GetBlobOutput;
            pub type Error = crate::blue_catbird::mlsChat::get_blob::GetBlobError<'static>;

            pub struct InputData {
                pub blob_id: String,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        blob_id: value.blob_id.into(),
                    }
                }
            }
        }

        pub mod get_blob_usage {
            pub const NSID: &str = "blue.catbird.mlsChat.getBlobUsage";

            pub type Output =
                crate::blue_catbird::mlsChat::get_blob_usage::GetBlobUsageOutput<'static>;
        }

        pub mod get_group_metadata_blob {
            pub const NSID: &str = "blue.catbird.mlsChat.getGroupMetadataBlob";

            pub type Input =
                crate::blue_catbird::mlsChat::get_group_metadata_blob::GetGroupMetadataBlob<
                    'static,
                >;
            pub type Output =
                crate::blue_catbird::mlsChat::get_group_metadata_blob::GetGroupMetadataBlobOutput;
            pub type Error =
                crate::blue_catbird::mlsChat::get_group_metadata_blob::GetGroupMetadataBlobError<
                    'static,
                >;

            pub struct InputData {
                pub blob_locator: Option<String>,
                pub group_id: String,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        blob_locator: value.blob_locator.map(Into::into),
                        group_id: value.group_id.into(),
                    }
                }
            }
        }

        pub mod put_group_metadata_blob {
            pub const NSID: &str = "blue.catbird.mlsChat.putGroupMetadataBlob";

            pub type Input =
                crate::blue_catbird::mlsChat::put_group_metadata_blob::PutGroupMetadataBlob;
            pub type Params =
                crate::blue_catbird::mlsChat::put_group_metadata_blob::PutGroupMetadataBlobParams<
                    'static,
                >;
            pub type Output =
                crate::blue_catbird::mlsChat::put_group_metadata_blob::PutGroupMetadataBlobOutput<
                    'static,
                >;
            pub type Error =
                crate::blue_catbird::mlsChat::put_group_metadata_blob::PutGroupMetadataBlobError<
                    'static,
                >;

            pub struct InputData {
                pub body: Vec<u8>,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        body: bytes::Bytes::from(value.body),
                    }
                }
            }

            pub struct ParamsData {
                pub blob_locator: String,
                pub group_id: String,
            }

            impl From<ParamsData> for Params {
                fn from(value: ParamsData) -> Self {
                    Self {
                        blob_locator: value.blob_locator.into(),
                        group_id: value.group_id.into(),
                    }
                }
            }
        }

        pub mod upload_blob {
            pub const NSID: &str = "blue.catbird.mlsChat.uploadBlob";

            pub type Input = crate::blue_catbird::mlsChat::upload_blob::UploadBlob;
            pub type Output = crate::blue_catbird::mlsChat::upload_blob::UploadBlobOutput<'static>;
            pub type Error = crate::blue_catbird::mlsChat::upload_blob::UploadBlobError<'static>;

            pub struct InputData {
                pub body: Vec<u8>,
            }

            impl From<InputData> for Input {
                fn from(value: InputData) -> Self {
                    Self {
                        body: bytes::Bytes::from(value.body),
                    }
                }
            }
        }
    }

    pub mod mls_ds {
        pub mod deliver_message {
            pub const NSID: &str = "blue.catbird.mlsDS.deliverMessage";
            pub type Input = crate::blue_catbird::mlsDS::deliver_message::DeliverMessage<'static>;
            pub type Output =
                crate::blue_catbird::mlsDS::deliver_message::DeliverMessageOutput<'static>;
        }

        pub mod deliver_welcome {
            pub const NSID: &str = "blue.catbird.mlsDS.deliverWelcome";
            pub type Input = crate::blue_catbird::mlsDS::deliver_welcome::DeliverWelcome<'static>;
            pub type Output =
                crate::blue_catbird::mlsDS::deliver_welcome::DeliverWelcomeOutput<'static>;
        }

        pub mod fetch_key_package {
            pub const NSID: &str = "blue.catbird.mlsDS.fetchKeyPackage";
            pub type Output =
                crate::blue_catbird::mlsDS::fetch_key_package::FetchKeyPackageOutput<'static>;
        }

        pub mod get_convo_digest {
            pub const NSID: &str = "blue.catbird.mlsDS.getConvoDigest";
            pub type Output =
                crate::blue_catbird::mlsDS::get_convo_digest::GetConvoDigestOutput<'static>;
        }

        pub mod get_convo_events {
            pub const NSID: &str = "blue.catbird.mlsDS.getConvoEvents";
            pub type Output =
                crate::blue_catbird::mlsDS::get_convo_events::GetConvoEventsOutput<'static>;
        }

        pub mod submit_commit {
            pub const NSID: &str = "blue.catbird.mlsDS.submitCommit";
            pub type Input = crate::blue_catbird::mlsDS::submit_commit::SubmitCommit<'static>;
            pub type Output =
                crate::blue_catbird::mlsDS::submit_commit::SubmitCommitOutput<'static>;
        }

        pub mod transfer_sequencer {
            pub const NSID: &str = "blue.catbird.mlsDS.transferSequencer";
            pub type Input =
                crate::blue_catbird::mlsDS::transfer_sequencer::TransferSequencer<'static>;
            pub type Output =
                crate::blue_catbird::mlsDS::transfer_sequencer::TransferSequencerOutput<'static>;
        }

        pub mod health_check {
            pub const NSID: &str = "blue.catbird.mlsDS.healthCheck";
            pub type Output = crate::blue_catbird::mlsDS::health_check::HealthCheckOutput<'static>;
        }

        pub mod get_federation_peers {
            pub const NSID: &str = "blue.catbird.mlsDS.getFederationPeers";
            pub type Output =
                crate::blue_catbird::mlsDS::get_federation_peers::GetFederationPeersOutput<'static>;
        }

        pub mod upsert_federation_peer {
            pub const NSID: &str = "blue.catbird.mlsDS.upsertFederationPeer";
            pub type Input =
                crate::blue_catbird::mlsDS::upsert_federation_peer::UpsertFederationPeer<'static>;
            pub type Output =
                crate::blue_catbird::mlsDS::upsert_federation_peer::UpsertFederationPeerOutput<
                    'static,
                >;
        }

        pub mod delete_federation_peer {
            pub const NSID: &str = "blue.catbird.mlsDS.deleteFederationPeer";
            pub type Input =
                crate::blue_catbird::mlsDS::delete_federation_peer::DeleteFederationPeer<'static>;
            pub type Output =
                crate::blue_catbird::mlsDS::delete_federation_peer::DeleteFederationPeerOutput<
                    'static,
                >;
        }

        pub mod get_federation_mode {
            pub const NSID: &str = "blue.catbird.mlsDS.getFederationMode";
            pub type Output =
                crate::blue_catbird::mlsDS::get_federation_mode::GetFederationModeOutput<'static>;
        }

        pub mod set_federation_mode {
            pub const NSID: &str = "blue.catbird.mlsDS.setFederationMode";
            pub type Input =
                crate::blue_catbird::mlsDS::set_federation_mode::SetFederationMode<'static>;
            pub type Output =
                crate::blue_catbird::mlsDS::set_federation_mode::SetFederationModeOutput<'static>;
        }
    }
}

#[cfg(test)]
mod bytes_test {
    use crate::catbird::mls_chat::register_device;

    #[test]
    fn test_bytes_serialization_format() {
        let input: register_device::Input = register_device::InputData {
            device_uuid: Some("test-uuid".to_string()),
            device_name: "Test Device".to_string(),
            signature_public_key: vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
            key_packages: vec![],
        }
        .into();
        let json = serde_json::to_string_pretty(&input).unwrap();
        println!("=== SERIALIZED JSON ===\n{}\n=== END ===", json);

        // Check that signaturePublicKey uses $bytes format
        assert!(
            json.contains("\"$bytes\""),
            "Expected $bytes format but got: {}",
            json
        );
    }
}
