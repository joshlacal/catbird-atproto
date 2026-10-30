#!/usr/bin/env python3
"""Project the shared core/overlay corpus through mls-codegen reproducibly.

Checkpoint this repository with jj before `generate`. The `check` action writes
only to temporary staging and verifies the complete committed generated tree.
"""

import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def fingerprint(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def normalize_projection(stage):
    # Namespace feature gates belong to the reproducible projection rather than
    # one-off edits to the generated module index. mls-codegen has no option to
    # gate a namespace module behind a Cargo feature, so this is the one
    # documented post-generation step. Byte codecs for named bytes refs and the
    # raw labyrinthRelay output codec come from mls-codegen itself.
    index = stage / "com_atproto.rs"
    text = index.read_text()
    for namespace in ["space", "memberspace", "managedspace", "personalspace"]:
        marker = f"pub mod {namespace};"
        if text.count(marker) != 1:
            raise ValueError(f"Expected one generated {namespace} module")
        text = text.replace(marker, '#[cfg(feature = "namespace-atproto-space")]\n' + marker)
    index.write_text(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["generate", "check"])
    parser.add_argument("--generator", required=True, type=Path, help="Built mls-codegen gen-lexicons executable")
    parser.add_argument("--core-lexicons", type=Path, default=ROOT.parent / "Petrel/generator/lexicons")
    parser.add_argument("--overlay-lexicons", type=Path, default=ROOT.parent / "PetrelCatbird/lexicons")
    args = parser.parse_args()
    staging = Path(tempfile.mkdtemp(prefix="catbird-atproto-codegen-"))
    stage = staging / "generated"
    subprocess.run([str(args.generator.resolve()), "--lexdir", str(args.core_lexicons),
                    "--lexdir", str(args.overlay_lexicons), "--outdir", str(stage)], check=True)
    normalize_projection(stage)
    paths = sorted(stage.rglob("*.rs"))
    for offset in range(0, len(paths), 80):
        subprocess.run(["rustfmt", "--edition", "2021", *map(str, paths[offset:offset + 80])], check=True)
    target = ROOT / "src/generated"
    if args.action == "check":
        expected, actual = fingerprint(stage), fingerprint(target)
        if expected != actual:
            changed = sorted(name for name in expected.keys() | actual.keys()
                             if expected.get(name) != actual.get(name))
            raise SystemExit(f"Generated projection differs: {changed}")
        print(f"Roundtrip verified: {len(expected)} generated files")
    else:
        if target.exists():
            shutil.move(str(target), str(staging / "previous"))
        shutil.move(str(stage), str(target))
        print(f"Generated {len(paths)} Rust files; previous tree retained at {staging / 'previous'}")


if __name__ == "__main__":
    main()
