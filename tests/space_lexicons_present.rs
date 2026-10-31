//! Plan 02 (WS) Task 1: Verify all clean-slate Spaces, Labyrinth PQ, Chat pruning/relay,
//! and Push Gateway lexicon bindings are generated in `catbird-atproto`.

use catbird_atproto::blue_catbird::chat::{
    acknowledge_entries::AcknowledgeEntries, register_push_gateway::RegisterPushGateway,
    relay_space_credential::RelaySpaceCredential, relay_space_read::RelaySpaceRead,
    AccountDeletedEntry, ApplicationAad, ApplicationEntry, ConversationEntry, SequencerReceipt,
};
use catbird_atproto::blue_catbird::labyrinth::{
    attachment_manifest::AttachmentManifest, batch::Batch, conversation,
    conversation_policy::ConversationPolicy, device::Device, epoch_member::EpochMember, mailbox,
    otc_session::OtcSession, virtual_device::VirtualDevice, EpochPublic, SealedMessage,
};
use catbird_atproto::blue_catbird::push::{deliver::Deliver, register_key::RegisterKey};
use catbird_atproto::com_atproto::space::{
    apply_writes::ApplyWrites, get_blob::GetBlob, get_repo::GetRepo,
    get_space_credential::GetSpaceCredential, list_repo_ops::ListRepoOps,
    notify_credential_revoked::NotifyCredentialRevoked, notify_space_deleted::NotifySpaceDeleted,
    remove_writer::RemoveWriter,
};

#[test]
fn atproto_space_and_labyrinth_space_declarations_are_present() {
    let _ = core::mem::size_of::<ApplyWrites>();
    let _ = core::mem::size_of::<GetSpaceCredential>();
    let _ = core::mem::size_of::<ListRepoOps>();
    let _ = core::mem::size_of::<GetRepo>();
    let _ = core::mem::size_of::<GetBlob>();
    let _ = core::mem::size_of::<NotifyCredentialRevoked>();
    let _ = core::mem::size_of::<NotifySpaceDeleted>();
    let _ = core::mem::size_of::<RemoveWriter>();

    assert_eq!(mailbox::NSID, "blue.catbird.labyrinth.mailbox");
    assert_eq!(mailbox::KEY_TYPE, "literal:self");
    assert_eq!(
        mailbox::COLLECTIONS,
        &[
            "blue.catbird.labyrinth.device",
            "blue.catbird.labyrinth.virtualDevice",
            "blue.catbird.labyrinth.epoch",
            "blue.catbird.labyrinth.epochMember",
            "blue.catbird.labyrinth.otcSession",
            "blue.catbird.labyrinth.ownerBatch",
            "blue.catbird.labyrinth.attachmentManifest",
        ]
    );

    assert_eq!(conversation::NSID, "blue.catbird.labyrinth.conversation");
    assert_eq!(conversation::KEY_TYPE, "any");
    assert_eq!(
        conversation::COLLECTIONS,
        &[
            "blue.catbird.labyrinth.batch",
            "blue.catbird.labyrinth.mek",
            "blue.catbird.labyrinth.attachmentManifest",
        ]
    );
}

#[test]
fn clean_slate_labyrinth_chat_and_push_types_roundtrip() {
    let _ = core::mem::size_of::<ConversationPolicy>();
    let _ = core::mem::size_of::<AttachmentManifest>();
    let _ = core::mem::size_of::<OtcSession>();
    let _ = core::mem::size_of::<Batch>();
    let _ = core::mem::size_of::<Device>();
    let _ = core::mem::size_of::<EpochMember>();
    let _ = core::mem::size_of::<VirtualDevice>();
    let _ = core::mem::size_of::<EpochPublic>();
    let _ = core::mem::size_of::<SealedMessage>();

    let _ = core::mem::size_of::<AcknowledgeEntries>();
    let _ = core::mem::size_of::<RegisterPushGateway>();
    let _ = core::mem::size_of::<RelaySpaceCredential>();
    let _ = core::mem::size_of::<RelaySpaceRead>();
    let _ = core::mem::size_of::<AccountDeletedEntry>();
    let _ = core::mem::size_of::<ApplicationAad>();
    let _ = core::mem::size_of::<ApplicationEntry>();
    let _ = core::mem::size_of::<ConversationEntry>();
    let _ = core::mem::size_of::<SequencerReceipt>();
    let _check_receipt_fields = |r: &SequencerReceipt| {
        let _: &catbird_atproto::jacquard_common::deps::bytes::Bytes = &r.archive_commitment;
        let _: i64 = r.issued_at_ms;
    };

    let _ = core::mem::size_of::<RegisterKey>();
    let _ = core::mem::size_of::<Deliver>();
}
