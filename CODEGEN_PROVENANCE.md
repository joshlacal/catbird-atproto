# Generated Rust lexicon provenance

This record covers `src/generated/blue_catbird/chat.rs` at
`8d0026d4c1423b23d2def751fc88b36c3a1b949c`.

## Canonical command

Run from the `Catbird+Petrel` workspace root, after checkpointing the
`catbird-atproto` working copy with jj:

```sh
cargo run --manifest-path mls-ds/Cargo.toml -p mls-codegen -- \
  --lexdir Petrel/generator/lexicons \
  --lexdir PetrelCatbird/lexicons \
  --outdir catbird-atproto/src/generated
find catbird-atproto/src/generated -name '*.rs' -print0 | xargs -0 rustfmt
```

The command is the repository-authoritative Jacquard path documented in
`catbird-atproto/CLAUDE.md`; `mls-codegen` invokes Jacquard 0.12.1 and applies
the generated-file lint normalization.

## Pinned inputs and hashes

The clean-room reproduction used these exact jj commit IDs:

| Input | Revision |
| --- | --- |
| `Petrel/generator/lexicons` | `b59b3d457d2c4796df27c58740a2528f1dd2bfa0` |
| `PetrelCatbird/lexicons` | `8ec8acaa1137b68b57b78ebfaea9404d5923305b` |
| `mls-ds/codegen` | `00c16517d4e3032afa677310549f7660d07f7b78` |

The source revision is a local jj commit which is not exported as a Git
object. Its deterministic content-record hashes are SHA-256 over sorted lines
of `SHA256(file-bytes)  path`; the specific schema blob is hashed directly:

```text
PetrelCatbird/lexicons tree:                 e06f60133a21eb6d1b0c147e227e7c39e1bae362730895e83c87ea3a529192ba
PetrelCatbird blue.catbird.chat subset:      fa43ff27373981c23f23360c17c249526a1baeaedac68a6fa761e812ef41e054
blue.catbird.chat.defs.json blob (SHA-256):  88fb17ca9ca2bcc605c22123ba3ae801b2baf1f725afe85934680b5cd2f66c7a
```

The regenerated `src/generated/blue_catbird/chat.rs` is byte-identical to
the committed file:

```text
ae514c3c58f1cc2712cdc2d0821d083023757883f409266bfe9560295fcbda56
```

The full generated directory is intentionally not claimed byte-identical in
this check: the pinned source corpus has unrelated changes in other
namespaces. No generated file was hand-edited and no lexicon semantics were
changed for this provenance repair.

## Task 0A / Finding 6: `com.atproto.space` v2 SignedCommit surface

This record covers `src/generated/com_atproto/space.rs` and `src/generated/com_atproto/space/`
at `catbird-atproto` revision `urpktszl` (`8bf6222d`, review baseline `edd245fc`), with initial generation performed at `3c0262dc`.

### Canonical generation command

Scoped generation using `jacquard-codegen` from `jacquard-lexgen` (Jacquard 0.13.0 / `3287244a99262a361bd32873a871982da0a76c40`):

```sh
cargo run --manifest-path jacquard/Cargo.toml -p jacquard-lexgen --bin jacquard-codegen -- \
  --macro \
  -i Petrel/generator/lexicons/com/atproto/space \
  -o catbird-atproto/src/generated
find catbird-atproto/src/generated/com_atproto/space* -name '*.rs' -print0 | xargs -0 rustfmt
```

### Pinned inputs and deterministic hashes

#### 1. Initial Generation Point

| Input | Revision / Path | SHA-256 |
| --- | --- | --- |
| `Petrel/generator/lexicons/com/atproto/space/defs.json` | `quurkpuz` (`b409d73d`) | `a81cdee945eebe4117f2b74d51a4298f0d5c47675412ec6f95944d99cf67291d` |
| `Petrel/generator/lexicons/com/atproto/space` (tree) | `quurkpuz` (`b409d73d`) | `99dac4a569e6632a295a486b155a673e343f6774c9e99d12a977518209a5bafa` |
| `jacquard` (repo/api/lexgen) | `vkylwwum` (`8d85e730`) (parent `3287244a`) | `3287244a99262a361bd32873a871982da0a76c40` |
| `catbird-atproto` | `urpktszl` (`3c0262dc`) | — |
| Protocol `.pin` | `89deb9faca20e56fa2a262fe9746ed52bc1095ba` | — |

#### 2. Current Immutable Verification Contract & Fixtures (Round 5 / Final Fix Round)

| Repository / Artifact | Revision / Path | SHA-256 |
| --- | --- | --- |
| `catbird-atproto` | `urpktszl` (`8bf6222d`, baseline `edd245fc`) | — |
| `Petrel` | `quurkpuz` (`10180663`, baseline `2a427363`) | — |
| `jacquard` | `vkylwwum` (`970d672a`, baseline `0280b77c`) (parent `3287244a`) | `3287244a99262a361bd32873a871982da0a76c40` |
| `Petrel/generator/lexicons/com/atproto/space/defs.json` | `10180663` | `a81cdee945eebe4117f2b74d51a4298f0d5c47675412ec6f95944d99cf67291d` |
| Portable Vector Fixture (`commit_v2_vectors.json`) | `tests/fixtures/commit_v2_vectors.json` | `85c60d19154ed59f3d3b06aa80a3738c32e72baecd82de15bf48baabc6f5bede` |

### Output artifact digest

```text
catbird-atproto/src/generated/com_atproto/space.rs (SHA-256): bcbc7db4cd1a550883a97e641b5c334d923b62f3b231d47fa4e3af68645963a8
jacquard-api/src/com_atproto/space.rs (SHA-256):              bcbc7db4cd1a550883a97e641b5c334d923b62f3b231d47fa4e3af68645963a8
```

The generated `SignedCommit` types in `catbird-atproto` and `jacquard-api` are byte-identical.

### Contract & Verification Rules

1. **Wire rule:** `SignedCommit` requires only `ver`, `rev`, `hash`, and `sig` on the wire so legacy v1 payloads deserialize; all v2 transition fields (`did`, `space`, `prevRev`, `prevHash`, `path`, `action`, action-appropriate `cid`/`prevCid`, and `val` digest) are required by all v2 signers and verifiers.
2. **Verification policy / fail closed default:** Generic verifiers default to `CommitVerificationPolicy::StrictV2` which fails closed on v1 commits. Bounded migration requires caller-selected `DualReadWithCutoff { cutoff_rev }` or explicit `ExplicitMigrationPermitV1`. Acceptance of v1 cannot be perpetual or unconfigured.
3. **Omission tests:** Missing or illegal fields across create/update/delete actions cause deterministic verification failures dynamically tested against canonical omission vector descriptors.
4. **Generic CAR fail-closed:** `PermissionedCar::validate` fails closed on untrusted v2 commits; caller-supplied trusted context is verified via `validate_v2` or `validate_with_policy`.
5. **Portable cross-boundary vectors:** Canonical fixed literal vectors for transcripts, curves (Ed25519, NIST P-256, Secp256k1), CBOR, and omission vectors are published as self-contained fixtures in `catbird-atproto/tests/fixtures/commit_v2_vectors.json`, `Petrel/generator/tests/fixtures/commit_v2_vectors.json`, and `jacquard-repo/tests/fixtures/commit_v2_vectors.json`, exposed via `COMMIT_V2_TEST_VECTORS_JSON`, and consumed by tests across all three repositories without relative cross-workspace file dependencies.
6. **External producer & release status:** Producer deployment owner remains UNKNOWN and external producer deployment remains an operational rollout gate. Consumer cutover is explicitly Task 5 and external producer deployment is Task 11. Release of v2 enforcement in deployed consumers is BLOCKED until the accountable producer is deployed and consumer cutover is executed. Local reproducibility does not imply deployed reproducibility.

## Native leaf recovery and signed operation expiry (2026-09-05)

The two endpoint files below were regenerated on the existing `d3536e0f`
main tree without replacing its Space, Circle, runtime, or dependency surface.
The canonical PetrelCatbird chat schemas provide the optional
`pendingLeafRecoveryRequests` response field and `SignedOperationExpired` error.

Generation used Jacquard 0.13.0 at
`3287244a99262a361bd32873a871982da0a76c40`, matching this crate's dependency pin.
A scoped wrapper loads a copy of the 36 canonical
`PetrelCatbird/lexicons/blue/catbird/chat/*.json` schemas with
`LexiconCorpus::load_from_dir`, then calls
`CodeGenerator::with_mode(&corpus, "crate::generated".to_owned(), CodegenMode::Macro)`
and `write_to_disk` into a separate output directory. This uses the same
module root as the existing canonical Rust generator; the upstream CLI's
hardcoded `crate` root would produce different paths. Only the two listed
endpoint files were copied into this tree after `rustfmt --edition 2021`.
No generated file was hand-edited.

The generator's existing per-variant serde omission attributes are retained.
Focused tests cover typed expiry decoding, message preservation, and decoding
an absent message with the existing explicit-null serialization form; the
existing Space contract suite remains enabled.

| Input or generated output | SHA-256 |
| --- | --- |
| PetrelCatbird chat `blue.catbird.chat.getConversationState.json` | `75b2e89a35423d704fe4ca95ff0634be6d936013fa563be569c04bcbb8ea51eb` |
| PetrelCatbird chat `blue.catbird.chat.submitTransition.json` | `f843e0ee461008a116676038dabc49b1a1f351a1f06ae03672518a014acd9805` |
| Generated chat `get_conversation_state.rs` | `8748643995027c4a4ce3055eae4fb67f3b944f19252ab528e3955df6635eb301` |
| Generated chat `submit_transition.rs` | `937633a9d2102b980180b4ac3f1eb1cca7212335fc1863e1a1d57c9066de96ea` |

## Upstream `com.atproto.space` v1 SignedCommit restoration (2026-10-01)

This section supersedes "Task 0A / Finding 6" above. The v2 authenticated
transition `SignedCommit` shape was a Catbird invention that upstream never
adopted (decision D in `Catbird+Petrel/docs/DECISIONS.md`). Petrel
re-vendored `com.atproto.space` and `com.atproto.simplespace` verbatim from
bluesky-social/atproto PR #5187 at
`57b0a0424fb27d8e4989e74fa37fbc0ce4527ded` (Petrel bookmark
`spaces-upstream-defs-20261001`). `SignedCommit` now carries only `ver`,
`hash`, `ikm`, `sig`, `mac`, and `rev`, all required. The v2 vector fixture
`tests/fixtures/commit_v2_vectors.json` and its tests were retired.

### Generation

`mls-codegen` from mls-ds `d23bea50` (Jacquard 0.13.0 at
`3287244a99262a361bd32873a871982da0a76c40`, matching this crate's pin) was run
twice into scratch directories, each followed by `rustfmt --edition 2021`:

1. baseline: Petrel `747c83bf` lexicons + PetrelCatbird `045e4e9c` lexicons;
2. new: the re-vendored Petrel lexicons + the same PetrelCatbird lexicons.

A full-tree replacement would have rewritten 459 unrelated files
(`::core` vs `core` paths, module-root and feature-gate differences from the
mixed generation history above). Only the files whose output differs between
the two runs were copied in verbatim:

- `src/generated/com_atproto/space.rs`
- `src/generated/com_atproto/space/notify_credential_revoked.rs` (new)
- `src/generated/com_atproto/simplespace.rs`
- `src/generated/com_atproto/simplespace/{check_user_access,create_space,get_space,list_members,update_space,put_member}.rs`
- `src/generated/com_atproto/simplespace/add_member.rs` removed (upstream renamed it `putMember`)

No generated file was hand-edited.

| Input or output | SHA-256 |
| --- | --- |
| Petrel `com/atproto/space/defs.json` | `e46a24653498f62bdcd7a0529edd572e526669595b4b5bb513c94b9113d46601` |
| Generated `src/generated/com_atproto/space.rs` | `5427607e7db9b8ab258edcf5d47ad7126d4eb9802530d48ad97419fea5401670` |
