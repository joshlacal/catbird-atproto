#![allow(non_snake_case)]

extern crate alloc;

#[allow(
    clippy::manual_strip,
    clippy::needless_update,
    clippy::new_ret_no_self,
    clippy::new_without_default,
    clippy::type_complexity,
    clippy::unit_arg,
    clippy::unnecessary_lazy_evaluations
)]
pub mod generated {
    #[cfg(feature = "namespace-bluecatbird")]
    pub mod blue_catbird;
    pub mod builder_types;
    #[cfg(feature = "namespace-site-standard")]
    pub mod com_atproto;
    #[cfg(feature = "namespace-site-standard")]
    pub mod site_standard;
}

#[cfg(feature = "namespace-bluecatbird")]
pub use generated::blue_catbird;
pub use generated::builder_types;
#[cfg(feature = "namespace-site-standard")]
pub use generated::site_standard;
pub use jacquard_common;
pub use jacquard_common::types;
pub use jacquard_derive;

#[cfg(feature = "namespace-bluecatbird")]
pub mod catbird {
    pub mod bsky_chat {
        pub mod push_heartbeat {
            pub const NSID: &str = "blue.catbird.bskychat.pushHeartbeat";
        }
        pub mod update_mute_status {
            pub const NSID: &str = "blue.catbird.bskychat.updateMuteStatus";
        }
    }

    pub mod mls_ds {
        pub mod deliver_message {
            pub const NSID: &str = "blue.catbird.mlsDS.deliverMessage";
            pub type Input = crate::blue_catbird::mlsDS::deliver_message::DeliverMessage;
            pub type Output = crate::blue_catbird::mlsDS::deliver_message::DeliverMessageOutput;
        }

        pub mod deliver_welcome {
            pub const NSID: &str = "blue.catbird.mlsDS.deliverWelcome";
            pub type Input = crate::blue_catbird::mlsDS::deliver_welcome::DeliverWelcome;
            pub type Output = crate::blue_catbird::mlsDS::deliver_welcome::DeliverWelcomeOutput;
        }

        pub mod fetch_key_package {
            pub const NSID: &str = "blue.catbird.mlsDS.fetchKeyPackage";
            pub type Output = crate::blue_catbird::mlsDS::fetch_key_package::FetchKeyPackageOutput;
        }

        pub mod get_convo_digest {
            pub const NSID: &str = "blue.catbird.mlsDS.getConvoDigest";
            pub type Output = crate::blue_catbird::mlsDS::get_convo_digest::GetConvoDigestOutput;
        }

        pub mod get_convo_events {
            pub const NSID: &str = "blue.catbird.mlsDS.getConvoEvents";
            pub type Output = crate::blue_catbird::mlsDS::get_convo_events::GetConvoEventsOutput;
        }

        pub mod submit_commit {
            pub const NSID: &str = "blue.catbird.mlsDS.submitCommit";
            pub type Input = crate::blue_catbird::mlsDS::submit_commit::SubmitCommit;
            pub type Output = crate::blue_catbird::mlsDS::submit_commit::SubmitCommitOutput;
        }

        pub mod transfer_sequencer {
            pub const NSID: &str = "blue.catbird.mlsDS.transferSequencer";
            pub type Input = crate::blue_catbird::mlsDS::transfer_sequencer::TransferSequencer;
            pub type Output =
                crate::blue_catbird::mlsDS::transfer_sequencer::TransferSequencerOutput;
        }

        pub mod health_check {
            pub const NSID: &str = "blue.catbird.mlsDS.healthCheck";
            pub type Output = crate::blue_catbird::mlsDS::health_check::HealthCheckOutput;
        }

        pub mod get_federation_peers {
            pub const NSID: &str = "blue.catbird.mlsDS.getFederationPeers";
            pub type Output =
                crate::blue_catbird::mlsDS::get_federation_peers::GetFederationPeersOutput;
        }

        pub mod upsert_federation_peer {
            pub const NSID: &str = "blue.catbird.mlsDS.upsertFederationPeer";
            pub type Input =
                crate::blue_catbird::mlsDS::upsert_federation_peer::UpsertFederationPeer;
            pub type Output =
                crate::blue_catbird::mlsDS::upsert_federation_peer::UpsertFederationPeerOutput;
        }

        pub mod delete_federation_peer {
            pub const NSID: &str = "blue.catbird.mlsDS.deleteFederationPeer";
            pub type Input =
                crate::blue_catbird::mlsDS::delete_federation_peer::DeleteFederationPeer;
            pub type Output =
                crate::blue_catbird::mlsDS::delete_federation_peer::DeleteFederationPeerOutput;
        }

        pub mod get_federation_mode {
            pub const NSID: &str = "blue.catbird.mlsDS.getFederationMode";
            pub type Output =
                crate::blue_catbird::mlsDS::get_federation_mode::GetFederationModeOutput;
        }

        pub mod set_federation_mode {
            pub const NSID: &str = "blue.catbird.mlsDS.setFederationMode";
            pub type Input = crate::blue_catbird::mlsDS::set_federation_mode::SetFederationMode;
            pub type Output =
                crate::blue_catbird::mlsDS::set_federation_mode::SetFederationModeOutput;
        }
    }
}

#[cfg(all(test, feature = "namespace-bluecatbird"))]
mod bytes_test {
    use crate::generated::blue_catbird::chat::SignedBlobDeletion;

    #[test]
    fn test_bytes_serialization_format() {
        let fixture = serde_json::json!({
            "body": {
                "actorDeviceId": "3b241101-e2bb-4255-8caf-4136c566a962",
                "actorDid": "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
                "authGeneration": 1,
                "blobId": "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
                "idempotencyKey": "8cb4f5d2-0d31-4b6f-a9c2-7e18f5403d61",
                "keyId": "key-1",
                "signatureDomain": "CATBIRD-CHAT-BLOB-DELETE",
                "signedAt": "2026-08-19T00:00:00.000Z"
            },
            "signature": {"$bytes": "AQIDBA=="}
        });
        let fixture_str = fixture.to_string();
        let deletion: SignedBlobDeletion = serde_json::from_str(&fixture_str).unwrap();
        let json = serde_json::to_string_pretty(&deletion).unwrap();
        println!("=== SERIALIZED JSON ===\n{}\n=== END ===", json);

        // Check that signature uses $bytes format
        assert!(
            json.contains("\"$bytes\""),
            "Expected $bytes format but got: {}",
            json
        );
    }
}
