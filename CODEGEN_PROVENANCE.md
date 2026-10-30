# Generated contract provenance

October 23 source reconciliation preserves the current chat recovery contracts and replaces the permissioned-data API with the exact October 22 upstream corpus. On October 29 the generated tree was re-baselined on the current `mls-codegen`, which now emits the byte and relay codecs that `Scripts/regenerate.py` used to add with regular-expression rewrites (review finding GC-1). On October 30 it was regenerated for the October 29, 2026 Spaces alpha (atproto `5d88b414`), which replaces `com.atproto.simplespace` with the `memberspace`, `managedspace` and `personalspace` policy namespaces. Full generation uses Petrel core and PetrelCatbird overlay sources together; no generated declarations are edited by hand. Local contract checks do not qualify a running host or application.

Current reproduction details are recorded below; historical provenance follows. Commands quoted in the historical records, including sections titled "Canonical command", are what was run at the time. The command under [Canonical regeneration](#canonical-regeneration) supersedes all of them.

## Canonical regeneration

There is one canonical regeneration command: `Scripts/regenerate.py`, run with the `gen-lexicons` binary built from mls-ds `codegen/` (the `mls-codegen` crate). Run it from this repository with `Petrel`, `PetrelCatbird` and `mls-ds` checked out beside it; the script reads `../Petrel/generator/lexicons` and `../PetrelCatbird/lexicons` by default. Running `mls-codegen` straight into `src/generated`, or the workspace-level `scripts/regenerate-atproto-types.sh`, skips the namespace gate and does not pin the `rustfmt` edition, so neither reproduces the committed tree.

The generator must come from mls-ds at or after all three of these generator fixes (mls-ds main `2df124d6` contains them):

- `11abdd83d` ("mls-codegen: inline refs to top-level bytes defs so Jacquard applies serde_bytes_helper"). Fields that refer to a named bytes definition, such as `#artifactHash` or `#identifierBytes`, get the same codec as inline bytes: JSON accepts `$bytes` and DAG-CBOR writes real byte strings.
- `ee9b1686` ("codegen: give schemaless application/json outputs raw-byte codecs"). `labyrinthRelay`, the only such output in this corpus, decodes and encodes the relayed body byte for byte.
- `4f980cb5` ("mls-codegen: Qualify union variants that Jacquard names alike"). Jacquard names a union arm that points at another lexicon's `main` definition after the last NSID segment and does not disambiguate such arms inside one two-segment namespace, so the October 29 `com.atproto.space` policy unions got three variants named `Policy`. The generator now names them `PersonalspacePolicy`, `MemberspacePolicy` and `ManagedspacePolicy`; the serde tags are unchanged.

An older generator omits those codecs or emits the colliding variants, and the script adds none of them. `check` reports the drift, and the `named_bytes_contract` and `labyrinth_relay_contract` tests cover both codecs.

```sh
# From this repository. Checkpoint with jj first: `generate` replaces src/generated.
jj new
cargo build --locked --manifest-path ../mls-ds/Cargo.toml -p mls-codegen --bin gen-lexicons
GEN=../mls-ds/target/debug/gen-lexicons   # or "$CARGO_TARGET_DIR/debug/gen-lexicons"
python3 Scripts/regenerate.py generate --generator "$GEN"
python3 Scripts/regenerate.py check --generator "$GEN"
cargo fmt --check
cargo test --locked --features streaming,namespace-atproto-space
cargo clippy --locked --all-targets --all-features
```

`Scripts/regenerate.py` runs the generator into temporary staging. It then gates the `com.atproto.space`, `com.atproto.memberspace`, `com.atproto.managedspace` and `com.atproto.personalspace` modules in `com_atproto.rs` behind the `namespace-atproto-space` feature. That gate is the only post-generation step, because `mls-codegen` has no option to put a module behind a Cargo feature. Next it formats every file with `rustfmt --edition 2021`. `generate` then replaces `src/generated` and keeps the previous tree in the temporary directory. `check` compares every generated file, including unexpected stale files, with the committed tree and changes nothing.

## Current generation (October 29 Spaces alpha, regenerated 2026-10-30)

The lexicon corpus is Petrel `generator/lexicons` at `92b05b81966c07a2a7d3d96a68f9230dd7787c5d` (bookmark `claude/spaces-oct29-20261030`, merged as Petrel main `e5b6039b`, PR #36; lexicons identical). Its `com/atproto/{space,memberspace,managedspace,personalspace}` lexicons are JSON-equal to atproto `5d88b414` (npm `0.0.0-spaces-alpha-20261029171913`), and `com/atproto/simplespace` is gone. PetrelCatbird `lexicons` is unchanged from the previous generation (its tree at `3208d02e38e9b7b176d8c2cf46d1e92feb555974` has the same aggregate as `8672c80f`).

The generator is mls-ds `codegen/` at `4f980cb51c8a9826c03eba4341db97d68091d567` (bookmark `claude/spaces-oct29-codegen-20261030`, merged as mls-ds main `2df124d6`, PR #63; `codegen/` and `Cargo.lock` identical), which is `f8c711a5` (`codex/spaces-release-20261023`) plus the union-variant fix above. Its `codegen/src/main.rs` before that fix is byte-identical to `63e696dc`. It was built with mls-ds's locked Cargo graph and Jacquard `3287244a99262a361bd32873a871982da0a76c40` (0.13.0), using Rust 1.97.1 and rustfmt 1.9.0 (edition 2021).

| Generator file | SHA-256 |
| --- | --- |
| mls-ds `codegen/src/main.rs` | `25f91cc12a6e1e42e77078fb171f6a3521a108cc82b9b95411c2e8ee853e56d8` |
| mls-ds `codegen/Cargo.toml` | `5d8756af56b27bfe9039c576e416f4652936fd1af4e84a996b278dfa251506b6` |
| mls-ds `Cargo.lock` | `d47a7f3031a614e13e7a576f94203e4fa39aebaba2a94af628879514e16c4050` |

| Input/output | Files | Aggregate SHA-256 |
| --- | ---: | --- |
| Petrel `generator/lexicons` | 441 | `a5c5fbc0a9c38ceb74192fa0aea31d93f73e381b3ddb02e55d73fef7f94e975d` |
| PetrelCatbird `lexicons` | 189 | `a627cf74bcf876c954f79cbc4b3cab6618a1eed2401385655310575bf63e853f` |
| Rust `src/generated` | 656 | `fa30c62726693ae02f750855015f51ea9667620c6ebc1b6adbefac2c81482320` |

The aggregates use the method described under the previous generation below.

### Change from the 2026-10-29 tree

Only the Spaces modules behind `namespace-atproto-space` change (25 paths, 2,399 lines added, 1,028 removed); every other generated file is byte-identical:

- `com_atproto/simplespace.rs` (the old policy defs) is removed. Its methods moved: `create_space`, `update_space`, `get_space` and `delete_space` to `com_atproto/space/`; `put_member`, `remove_member` and `list_members` to `com_atproto/memberspace/`; `check_user_access` to `com_atproto/managedspace/`.
- New policy types: `space::policy` (the published `com.atproto.space.policy` record), `memberspace::policy`, `memberspace::member` (the published member record), `managedspace::policy` and `personalspace::policy`. `createSpace`, `updateSpace`, `getSpace` and the policy record carry a `policy` union over the three policy types.
- New `com.atproto.space` methods: `clearRecords`, `removeWriter`, `importRepo`, `exportSpaceMeta` and `importSpaceMeta`.
- `space/get_space_credential.rs` changes only its `SpaceNotFound` description.

This is a breaking API change for Rust consumers that enable `namespace-atproto-space`. `catbird-mls` and `mls-ds` do not enable it. `nest/circle-appview` does; nest main (`035badce`, PR #26) pins `f40e8795`, whose tree is identical to this generation, and uses the `memberspace` and `managedspace` policy types instead of `com_atproto::simplespace`.

Verification on 2026-10-30 (macOS, Rust 1.97.1, rustfmt 1.9.0, Python 3.15.0):
`generate` wrote 656 files and renamed 12 colliding union variants (three in
each of `create_space`, `update_space`, `get_space` and `space::policy`). A
second run with `check` printed `Roundtrip verified: 656 generated files`.
`cargo fmt --check` passed. `cargo build --locked` passed with default
features, `--no-default-features`, `--features namespace-site-standard` and
`--all-features`. `cargo test --locked --features streaming,namespace-atproto-space`
passed 48 tests with 0 failures (20 in `com_atproto_space_surface`), and
`cargo test --locked` with default features passed 28.
`cargo clippy --locked --all-targets --all-features` exited 0 with the same 18
warnings in generated code as before (16 `len_zero`, 2 `result_large_err`).
`catbird-mls` (`cargo check --locked --lib`, path dependency on this tree)
compiled. These are local contract checks; they do not qualify a running host
or application.

## Previous generation (re-baselined 2026-10-29)

The generator is mls-ds `codegen/` at `63e696dc302b0f9454bf356ba0454ff5859691cf` (bookmark `codex/spaces-release-20261023`, mls-ds PR #62), which contains `11abdd83d` and `ee9b1686`. It was built with mls-ds's locked Cargo graph and Jacquard `3287244a99262a361bd32873a871982da0a76c40` (0.13.0, the same pin as this crate), using Rust 1.97.1 and rustfmt 1.9.0 (edition 2021).

| Generator file | SHA-256 |
| --- | --- |
| mls-ds `codegen/src/main.rs` | `8206a05d17053ce5eabe91e88fa08cee320627eaa340e260df713548e4ab7e17` |
| mls-ds `codegen/Cargo.toml` | `5d8756af56b27bfe9039c576e416f4652936fd1af4e84a996b278dfa251506b6` |
| mls-ds `Cargo.lock` | `137e23181784c9613b22eda115b78581c354f30b4fd734630ad778225112ab98` |

The lexicon corpus is unchanged from the October 22 alpha regeneration below. That is Petrel `generator/lexicons` at `4037e7760e2d1bb71db9a6cfdd0cd4134d4dd3bc`, whose lexicons are identical to the runtime pin `e115236537041a900ec971be05185a70cca73e8a`, and PetrelCatbird `lexicons` at `8672c80ffeb3b9cfbdb6bd98f66efa09b13fe0db`.

| Input/output | Files | Aggregate SHA-256 |
| --- | ---: | --- |
| Petrel `generator/lexicons` | 432 | `dda23340246bae282db0282257a03d016108b71f673bf6384c96e7528f07ecb6` |
| PetrelCatbird `lexicons` | 189 | `a627cf74bcf876c954f79cbc4b3cab6618a1eed2401385655310575bf63e853f` |
| Rust `src/generated` | 644 | `658975648f2676238891e66fbbf6def4f547023ed847736f2bd54b583b462481` |

Each aggregate is the SHA-256 of one line per file, written as the file's SHA-256, two spaces, its path relative to the directory, and LF. The lines are concatenated in Python `pathlib` sort order, which `Scripts/regenerate.py` also uses. That order compares paths one component at a time, so `com_atproto/...` sorts before `com_atproto.rs`. A byte-order sort of the path strings, such as `LC_ALL=C sort`, puts those the other way round and gives a different value for `src/generated`. Sorting whole lines, which sorts by hash, does not reproduce these values either. This command reproduces all three:

```sh
python3 -c 'import hashlib,pathlib,sys; r=pathlib.Path(sys.argv[1]); print(hashlib.sha256("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(r)}\n" for p in sorted(r.rglob("*")) if p.is_file()).encode()).hexdigest())' src/generated
```

### Change from the 2026-10-23 tree

The 2026-10-23 tree (`e7ff2a3b`, aggregate `ddaae592e19921ce41b3e5153b93b38de9f1d69f66cb1fffacfbd2e9b7e7f5d8`) came from an older `mls-codegen` with `main.rs` SHA-256 `f2d5432492f4675319a1209730ef43c4375e98e41c385c3ee929e0e50305f452`. Two regex rewrites in the script were applied on top. One added serde byte codecs to 73 fields typed by named bytes aliases; the other added the raw `labyrinthRelay` codec. The current generator does both, so the rewrites are gone. 643 of the 644 files are byte-identical, including `blue_catbird/labyrinth/labyrinth_relay.rs`, where the generator's codec equals the old rewrite. Only `blue_catbird/chat.rs` changes (499 lines added, 548 removed):

- 73 fields, with their 73 builder-state fields and 73 builder setters, are spelled `jacquard_common::deps::bytes::Bytes` instead of the `ArtifactHash` or `IdentifierBytes` alias. Both aliases are still generated as type aliases of `Bytes`, so the Rust types are identical. The serde byte-codec attributes are unchanged: the file has 149 `jacquard_common::serde_bytes_helper` and 2 `jacquard_common::opt_serde_bytes_helper` uses before and after.
- 24 `IdentifierBytes` fields regain the doc comment from `#identifierBytes`.
- In the embedded `blue.catbird.chat.defs` lexicon document, those 73 properties are inline `bytes` with the same 32- or 16-byte length bounds instead of `#artifactHash` or `#identifierBytes` refs.

The wire format is unchanged. `named_bytes_contract` covers JSON `$bytes` and DAG-CBOR byte strings for named and direct bytes; `labyrinth_relay_contract` covers the raw relay body. `com_atproto_space_surface` and `conversation_space_contract` exercise the Space wire shapes. These local contract checks do not qualify runtime authentication, migration, device rendering, or production interoperability.

Verification on 2026-10-29 (macOS, Rust 1.97.1, rustfmt 1.9.0, Python 3.15.0):
`generate` wrote 644 files, and the resulting diff is identical to the one an
earlier trial run of the same generator produced. A second run with `check`
printed `Roundtrip verified: 644 generated files`. `cargo fmt --check` passed.
`cargo build --locked` passed with default features and with `--all-features`.
`cargo test --locked --features streaming,namespace-atproto-space` passed 44
tests with 0 failures. `cargo clippy --locked --all-targets --all-features`
exited 0 with the same 18 warnings in generated code as the 2026-10-23 tree:
16 `len_zero` and 2 `result_large_err`, in the same files.

The generated module allows Clippy's `absurd_extreme_comparisons` lint because
Jacquard emits a literal `usize < 0` check for schema `minLength: 0`. This is
a redundant false condition, not a weakened field validator; handwritten code
does not inherit this generated-module-only allowance.

## October 22 alpha regeneration (2026-10-23)

The reviewed upstream is `bluesky-social/atproto` commit
`ac0c9f15392f6f0298d71dc52aa88c05036150be`, snapshot
`0.0.0-spaces-alpha-20261022141228`. Its source archive SHA-256 is
`eae029a70a3adf0f7d6241814d5a91d55bf6768e8f4cd00196870c911df57eb5`.
Petrel's `generator/provenance/spaces.json` records all 30 exact schema bytes;
`Scripts/space_lexicon_provenance.py verify --archive ARCHIVE` checks both the
complete alpha namespace inventory and archive provenance.

This generation reconciles Rust parent revisions
`142e1d96880afdc4c207a54020648dcb9695d771` and
`8bab4018ba20ff0342edf2ec8922304e5dd2cdbc`. Private input retains the newer chat
security contracts, Labyrinth history, and immutable conversation-Space
placement/generation contract, current authority policy lookup, permanent generation deletion, and complete-redaction item counts (schema revision
`1c8f6139781f51764c4829cdcb66c273ef7f787c`). The corpus fingerprints are
the ones in the current table above. The output of this generation was
superseded on 2026-10-29:

| Input/output | Files | Aggregate SHA-256 |
| --- | ---: | --- |
| Petrel `generator/lexicons` | 432 | `dda23340246bae282db0282257a03d016108b71f673bf6384c96e7528f07ecb6` |
| PetrelCatbird `lexicons` | 189 | `a627cf74bcf876c954f79cbc4b3cab6618a1eed2401385655310575bf63e853f` |
| Rust `src/generated` (superseded) | 644 | `ddaae592e19921ce41b3e5153b93b38de9f1d69f66cb1fffacfbd2e9b7e7f5d8` |

That tree was built with `gen-lexicons` from mls-ds `codegen/` whose
`main.rs` had SHA-256
`f2d5432492f4675319a1209730ef43c4375e98e41c385c3ee929e0e50305f452` and whose
Cargo manifest had SHA-256
`5d8756af56b27bfe9039c576e416f4652936fd1af4e84a996b278dfa251506b6`, with
Jacquard `3287244a99262a361bd32873a871982da0a76c40` (0.13.0), Rust 1.97.1
and rustfmt 1.9.0. At that time `Scripts/regenerate.py` also rewrote the
generated output. It added byte-codec annotations to the 73 fields typed by
named bytes aliases, because that generator annotated inline bytes but not
named bytes refs, and it added the raw-body `labyrinthRelay` codec. Both
rewrites were removed with the 2026-10-29 re-baseline.

The terminal-deletion contract also declares `SpaceDeleted` for `findMeks` and
`getAttachmentBlob`. A deleted conversation storage generation returns no data;
callers must not rebind or fall back to another placement. The overlay merges
current main `3dc8b613abbab900f650f7e1a4e42884cc42b0e1` while retaining all 48
main-only source changes plus the newer chat security definitions.

## Historical October chat provenance

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

## Labyrinth namespace and `participantView.labyrinthHead` (2026-10-11)

This regen adds the generated `blue.catbird.labyrinth.*` namespace, the
optional `labyrinthHead` field on `blue.catbird.chat.defs#participantView`
(with its `#labyrinthHead` object), and protocol version `"2"` on
`blue.catbird.chat.declaration`. It replaces the hand-written
`LabyrinthHead` shim mls-ds used on `labyrinth-backend-20261004`. The base is
`integration/clean-chat-merge-20261004` (`5819783a`).

### Canonical command

Run from a workspace root holding `Petrel`, `PetrelCatbird`, `mls-ds` and
`catbird-atproto`, into a scratch output directory:

```sh
cargo run --manifest-path mls-ds/Cargo.toml -p mls-codegen -- \
  --lexdir Petrel/generator/lexicons \
  --lexdir PetrelCatbird/lexicons \
  --outdir "$RAW"
cp -R "$RAW" "$CANON"
find "$CANON" -name '*.rs' -print0 | xargs -0 rustfmt
```

### Scope

A full regen at these inputs also changes `lib.rs`, 62 `com_atproto` files
(different Petrel lexicon revision) and `blue_catbird/circle.rs` (this
PetrelCatbird line has no Circle Space declaration). None of that was
copied. Only these generator outputs were copied in, unmodified:

| File | Source |
| --- | --- |
| `blue_catbird/labyrinth.rs`, `blue_catbird/labyrinth/` (46 files) | `$CANON` (rustfmt, as the rest of the tree) |
| `blue_catbird/chat/declaration.rs` | `$CANON` |
| `blue_catbird/chat.rs` | `$RAW` |
| `blue_catbird.rs` | `$RAW` |

`chat.rs` and `blue_catbird.rs` are committed on the base without rustfmt
(the raw output reproduces the base files exactly apart from the Labyrinth
additions), so they were taken from `$RAW` to keep the diff to the new
definitions. No generated file was hand-edited.

### Pinned inputs

| Input | jj change / commit |
| --- | --- |
| `Petrel/generator/lexicons` | `qlruxysw` / `c3310596874757e8ee2940892d5bc37368b4e75b` (local) |
| `PetrelCatbird/lexicons` | `rwyusyut` / `4d6c2b1d329e434a8a05a57d57cb20002ea858e1` (local; sits on unpushed local main) |
| `mls-ds/codegen` | `slmrqksv` / `5210cfdcb030ca6edce11984ca2d00f62ef91b7e` (`labyrinth-backend-20261004`) |
| rustfmt | 1.9.0-stable (8bab26f4f6 2026-07-14) |

The Labyrinth lexicons are published on PetrelCatbird branch
`labyrinth-head-regen-20261011` (`55e4eff49f45c14f5240b3211ec2c81ae76b3c22`),
a lexicon-only port onto PetrelCatbird `main`. Its
`lexicons/blue/catbird/labyrinth` tree has the same hash as below, and the
same command over it produces byte-identical `blue_catbird/labyrinth.rs`,
`blue_catbird/labyrinth/` and `blue_catbird/chat/declaration.rs`, and the same
`labyrinthHead` additions in `chat.rs`. Its `chat.rs` differs elsewhere only
because PetrelCatbird `main` does not yet have the encrypted-request chat
lexicons this crate's base already carries.

Tree hashes are SHA-256 over sorted lines of `SHA256(file-bytes)  path`:

| Input or generated output | SHA-256 |
| --- | --- |
| `PetrelCatbird/lexicons` tree (`*.json`) | `0ab028c047bb9d8d3351b87204b56db98c74c2183b684d93432a9514ad7f72ad` |
| `PetrelCatbird/lexicons/blue/catbird/labyrinth` tree | `305f594868979202eeda53dcdc1e0dc2471b70a0cd9bb9db966cad8e8b166b5a` |
| `Petrel/generator/lexicons` tree (`*.json`) | `1f8da52e6a2ed2ba4696d85d26ae4234c55e68a95e1ac8eba7c2182e4653cc83` |
| `blue.catbird.chat.defs.json` blob | `d830abb92430704e52aaf0b47eda435a01be9fd1d5f61d52daf42c2b22a48bcd` |
| `blue.catbird.chat.declaration.json` blob | `99532fb6e3a2b52b7d34c568b15865b501d5b227947d655a6513734a0595ca92` |
| Generated `blue_catbird/chat.rs` | `d2291a52f9b5a3777882d03ada4d3f81983268bb8c9bbec1c3a24e258203f86e` |
| Generated `blue_catbird/chat/declaration.rs` | `d8a9205e955c4110f7065662af00b966325fc0c32b336a988b37222ee0a136fe` |
| Generated `blue_catbird.rs` | `a6bd3d81d167daea2ecbb03721fe7f0a429052fc7b2792ce992112c954ce9830` |
| Generated `blue_catbird/labyrinth.rs` | `827091893d3a1e417035a067609d4537796ab85ec4caec5691aefeb60dc13ae0` |
| Generated `blue_catbird/labyrinth/` tree | `3b8d9f12c8969dc2ae4be49da9cd21a5c35e9e25a6b65dc69465d3e947200c95` |

### Verification

- `catbird-atproto`: `cargo check` passes.
- `mls-ds` at `labyrinth-backend-20261004` (`5210cfdc`), no shim:
  `cargo check --workspace --all-targets --features catbird-server/test-support`
  passes, and
  `conversation_state_response_carries_participant_labyrinth_head` passes.
- `catbird-mls` at `labyrinth-backend-20261004` (`06349f0b`), with
  `labyrinth` at `main` (`f18a3471`):
  `cargo check --features labyrinth --all-targets` passes.

## `labyrinthRelay` raw-byte output (2026-10-14)

`labyrinthRelay` declares `output.encoding: "application/json"` with no
schema: the response is the relayed endpoint's body, byte for byte.
Jacquard generated a raw `LabyrinthRelayOutput { body }` but kept the
default JSON codec, so decoding a relayed body failed (Codex P1 on #10).
mls-codegen now gives every schemaless `application/json` output the raw
`encode_output`/`decode_output` Jacquard already emits for other raw
encodings (mls-ds `codegen/src/main.rs`, `patch_schemaless_json_outputs`).
In this corpus `labyrinthRelay` is the only such output.

Regenerated with the canonical command above, with mls-codegen at mls-ds
`ee9b1686e295` (branch `claude/project-thread-3h43ay`, mls-ds #57), Petrel
`c4f915c98fb3` (local) and PetrelCatbird `55e4eff49f45` (PetrelCatbird #5, now on
`main`). Only the new `XrpcResp` codec methods in
`blue_catbird/labyrinth/labyrinth_relay.rs` were taken. The rest of that
regen differs only by unrelated drift (a newer Petrel revision, and
`::core::marker::PhantomData` instead of `core::marker::PhantomData`).
With that one import line rewritten, the committed file equals the
regenerated file:

| Generated output | SHA-256 |
| --- | --- |
| `blue_catbird/labyrinth/labyrinth_relay.rs` as regenerated | `9060bc6d6085c44c9d78b23c8212338f1ee2619fda7bd7b9f8efa1c965a60681` |

`tests/labyrinth_relay_contract.rs` checks that a relayed JSON body survives
decode and encode unchanged.


## Historical October 1 Spaces provenance

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

## atproto Spaces October 1, 2026 alpha (2026-10-02)

This section extends the 2026-10-01 restoration above to the October 1 alpha
release of atproto Spaces (atproto `679724ad62eb9a02f7f40429c3c4fdd65d3e4c79`,
published as npm `0.0.0-spaces-alpha-20261001173819`). Petrel re-vendored
`com.atproto.space` and `com.atproto.simplespace` from that commit in
`f2b76d1a769f3ca66871755b51f0988734fbfc8b`, an ancestor of the Petrel lane
bookmark `spaces-oct1-20261002` (that bookmark was at `16dffa8d` when this was
written; the commits after `f2b76d1a` up to `16dffa8d` do not touch the
`space` or `simplespace` lexicons). Against the previous vendor (Petrel
`368b5f33bb68fc18b4b980733dba3c4a8f0be621`, atproto `57b0a042`) exactly five
lexicons changed:

- `space.notifyWrite`: `rev` renamed `repoRev`; optional `spaceRev` and
  `prevSpaceRev` (set only on notifications forwarded to syncers); new
  declared errors `SpaceNotFound` and `FutureRev`.
- `space.listRepos`: entries are `{did, repoRev, hash, spaceRev}`; the cursor
  is an exclusive space-revision checkpoint (plain string, no `tid` format)
  and is omitted on an empty page.
- `space.listSpaces`: query filter `type` renamed `spaceType`.
- `simplespace.createSpace`: required body field `type` renamed `spaceType`.
- `space.getSpaceCredential`: descriptions only (HTTP Message Signature
  binding instead of DPoP `cnf.jkt`).

`space.notifyCredentialRevoked` (`{space, credentials[1..100]}`) was already
present from the 2026-10-01 vendor; its lexicon is byte-identical at
`679724ad`, and the committed `notify_credential_revoked.rs` is byte-identical
to this run's output.

### Generation

Same method as 2026-10-01. `mls-codegen` from mls-ds `d23bea50810b`
(Jacquard 0.13.0 at `3287244a99262a361bd32873a871982da0a76c40`) was exported
with `jj file show` and built in a scratch directory, then run twice, each
followed by `rustfmt --edition 2021`:

1. baseline: Petrel `368b5f33` lexicons + PetrelCatbird `045e4e9c` lexicons;
2. new: Petrel `f2b76d1a` lexicons + the same PetrelCatbird lexicons.

The two output trees differ in exactly five files, which were copied in
verbatim; no module index changed and no generated file was hand-edited:

- `src/generated/com_atproto/space/notify_write.rs`
- `src/generated/com_atproto/space/list_repos.rs`
- `src/generated/com_atproto/space/list_spaces.rs`
- `src/generated/com_atproto/space/get_space_credential.rs`
- `src/generated/com_atproto/simplespace/create_space.rs`

Positive control: the baseline run reproduces the committed 2026-10-01
`create_space.rs`, `space.rs`, `simplespace.rs`, and every other file copied
on 2026-10-01 byte-for-byte. Older space files that predate that copy (for
example `notify_write.rs`) differed from the baseline only in `core::` vs
`::core::` and `crate::com_atproto` vs `crate::generated::com_atproto` paths,
the mixed-history drift noted above; the copied files now carry the
`mls-codegen` form, like the other files copied on 2026-10-01. The
`namespace-atproto-space` gates in `com_atproto.rs` and `lib.rs` are
untouched.

| Input or output | SHA-256 |
| --- | --- |
| mls-ds `d23bea50` `codegen/src/main.rs` | `f2d5432492f4675319a1209730ef43c4375e98e41c385c3ee929e0e50305f452` |
| Petrel `f2b76d1a` `space/*.json` + `simplespace/*.json` (aggregate; command below) | `8c5ea869f1658df5a31e8ec527b0c5f82ea5899f514f1b1087711ec16a8e22ec` |
| Petrel `com/atproto/space/notifyWrite.json` | `535cbfcdda1f6a2f399d4bb7d3c984ede0324f55651718e6604a93ce8dc9aec7` |
| Petrel `com/atproto/space/listRepos.json` | `43b60646969ca2df00014696a9ca86633716da97cc2cb0929348858ac38f2cb9` |
| Petrel `com/atproto/space/listSpaces.json` | `b10db2321de10cdc783804f7d8882ec99e4e76f417283e462f74624dd314d5b8` |
| Petrel `com/atproto/space/getSpaceCredential.json` | `95fb72626acb3c4011c4a3f19d1e9d57ce0410ac4e5243747810c35b84952de5` |
| Petrel `com/atproto/space/notifyCredentialRevoked.json` | `db181622dfceb534b08a0713a39725f13874d27d49d748e815f1f8a3b815d13e` |
| Petrel `com/atproto/simplespace/createSpace.json` | `36d260eae7230f543c5d88c2d33f101dd6150e297a9027507bce362a1cbec037` |
| Generated `space/notify_write.rs` | `bfd847aa69b1f3293c58e837ad7f097bbb0cbcb7e05f2843ffa69440ad1e50e6` |
| Generated `space/list_repos.rs` | `3b6e2c06c6b176d1a80634c1fd48d71699365bd6f5e7531f1acf04049e7c5571` |
| Generated `space/list_spaces.rs` | `1f3d1baafd5b3bf4a9f676eb8555151961bf3d01e8b8c2d2a79c6a9e3a31c508` |
| Generated `space/get_space_credential.rs` | `810386f9053cceed50097dd3a00cddf1e13d736713f2490421eee18da123c024` |
| Generated `simplespace/create_space.rs` | `eb58ca2993c20e1d79065fb7dbfed229292ae337bc276c9c68d03a62ff36e5fb` |

The per-file Petrel paths above are relative to `generator/lexicons/`. The
aggregate lexicon hash hashes paths relative to
`generator/lexicons/com/atproto`, and reproduces only from that directory:

```bash
cd Petrel/generator/lexicons/com/atproto   # at f2b76d1a
shasum -a 256 space/*.json simplespace/*.json | LC_ALL=C sort -k2 | shasum -a 256
```

### Consumer impact

These are breaking renames for struct-literal and field-access consumers
(`circle-appview`): `NotifyWrite.rev` becomes `repo_rev` and gains
`space_rev` / `prev_space_rev`; `list_repos::Repo.rev` becomes `repo_rev` and
gains a required `space_rev`; `ListSpaces.r#type` and `CreateSpace.r#type`
become `space_type` (builder methods `space_type` / `maybe_space_type`); the
`notifyWrite` response error type is now `NotifyWriteError` instead of
`GenericError`.

`tests/com_atproto_space_surface.rs` covers the new wire shapes: both
notifyWrite hops, the declared errors, listRepos entries and empty-page cursor
omission, an opaque cursor string, and the `spaceType` renames. Pre-Oct-1
bodies are rejected with the specific missing field.
