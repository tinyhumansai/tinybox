# TinyStorageDrivers v1 collection fixture

`documents.json` contains rows exported through the public document read port
after the released TinyBox v0.1.40 `DocumentBoxStore` and
`DocumentIndexStore` writers stored them in the in-memory v1.0.0 engine. The
rows include their actual collection, document id, body, schema, and expiry
metadata. The fixture is not a hand-authored approximation of the old driver
format.

Provenance: TinyBox tag `v0.1.40`, commit
`c2e34c5bc29af6d3f0b2c294d5b8971c905903cb`; the unchanged archived lockfile
pins `tinystoragedrivers-core` v1.0.0 at
`141fd9ed0ad5d14a8fb5a1b3e837a719e81ac08d`. Archive and generator source are
kept outside build output in `<tinybox-repository>/.epic-repositories/legacy-tinybox-v0140`.
The archived generator is an implicitly discovered example, so the original
manifests and lockfile remain byte-for-byte intact.

From the native TinyBox repository root, regenerate the archived source and
copy the generator into its example directory:

```sh
repo_root=$(git rev-parse --show-toplevel)
archive="$repo_root/.epic-repositories/legacy-tinybox-v0140"
fixture="$repo_root/crates/tinybox-bin/tests/fixtures/legacy-v0.1.40/collections"
mkdir -p "$archive" "$archive/vendor"
git archive v0.1.40 | tar -x -C "$archive"
git clone --no-checkout https://github.com/tinyhumansai/tinybus "$archive/vendor/tinybus"
git -C "$archive/vendor/tinybus" fetch --depth=1 origin 1f33d1be1901a2d44bfe674cd7cf294cf3848821
git -C "$archive/vendor/tinybus" checkout --detach 1f33d1be1901a2d44bfe674cd7cf294cf3848821
mkdir -p "$archive/crates/tinybox-drivers/examples"
cp "$fixture/write_document_fixture.rs" "$archive/crates/tinybox-drivers/examples/"
```

Run the public writer from the archive root, then replace the checked-in
artifact with its output:

```sh
repo_root=$(git rev-parse --show-toplevel)
archive="$repo_root/.epic-repositories/legacy-tinybox-v0140"
fixture="$repo_root/crates/tinybox-bin/tests/fixtures/legacy-v0.1.40/collections"
cd "$archive"
cargo run --locked -p tinybox-drivers --example write_document_fixture -- \
  "$fixture/generated"
cp "$fixture/generated/documents.json" "$fixture/documents.json"
```

The generated artifact SHA-256 is
`5819d903ba83bd0ede0ccc108a3e22b1ce56b54399045ca63eb63c0a4c5899e1`.
The regression seeds these exact rows into the current testkit and exercises
the current stores' open-time migration path and public read APIs.
