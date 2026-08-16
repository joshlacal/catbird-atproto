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
