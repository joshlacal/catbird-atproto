#!/usr/bin/env bash
# Build the rustdoc API site into _site/ (served at https://joshlacal.github.io/catbird-atproto/).
# Run from anywhere; sibling repos referenced by path dependencies must sit next to this repo.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export CMAKE_POLICY_VERSION_MINIMUM="${CMAKE_POLICY_VERSION_MINIMUM:-3.5}"

rm -rf _site target/doc
cargo doc --no-deps --locked --workspace --all-features
test -f "target/doc/catbird_atproto/index.html"
mkdir -p _site
cp -R target/doc/. _site/
touch _site/.nojekyll
cat > _site/index.html <<'HTML'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>catbird-atproto API documentation</title>
<link rel="canonical" href="catbird_atproto/index.html">
<meta http-equiv="refresh" content="0; url=catbird_atproto/index.html">
</head>
<body>
<p><a href="catbird_atproto/index.html">catbird-atproto API documentation</a></p>
</body>
</html>
HTML
echo "Docs site ready: _site/catbird_atproto/index.html"
