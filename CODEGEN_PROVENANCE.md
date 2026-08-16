# Generated Rust lexicon provenance

This record covers `src/generated/blue_catbird/chat.rs` at
`2f41bf7334a724a270bbd28b0d017853580d2db8`.

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
| `PetrelCatbird/lexicons` | `f2a095506ec9a5eda96e2226b84a80323a90cc21` |
| `mls-ds/codegen` | `00c16517d4e3032afa677310549f7660d07f7b78` |

Deterministic `git ls-tree` record hashes for those inputs are:

```text
Petrel/generator/lexicons: d356f3cce92b88ef17644412835662c5ad389519672a1dd0095363f86ce31819
PetrelCatbird/lexicons:    973ed5f973be034cea6ac0d1c98559182c49721e59520383d3a931173246d696
blue.catbird.chat subset:  28179d24b5cebfd628e9674525d90172dd9ae8c8e4a7166410a0983cf04580d7
mls-ds generator inputs:   2c78f8508366406e30634f7294fa909520469ad1f0bb043f68a22b655c496865
```

The regenerated `src/generated/blue_catbird/chat.rs` is byte-identical to
the committed file:

```text
015ff4086feff919ab6846aee0653a5d11b0878888e16457f4a85c2f596b6644
```

The full generated directory is intentionally not claimed byte-identical in
this check: the pinned source corpus has unrelated changes in other
namespaces. No generated file was hand-edited and no lexicon semantics were
changed for this provenance repair.
