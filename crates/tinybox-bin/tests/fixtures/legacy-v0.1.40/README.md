# TinyBox v0.1.40 file-store fixture

These JSON files were written by the released `tinybox-cli::FileStore` and
`tinybox-cli::FileTemplates` APIs from TinyBox v0.1.40 (commit
`c2e34c5bc29af6d3f0b2c294d5b8971c905903cb`). Its unchanged `Cargo.lock` pins
TinyStorageDrivers v1.0.0 at `141fd9ed0ad5d14a8fb5a1b3e837a719e81ac08d`.
The fixture is an authentic pre-migration writer sample; it does not claim to
come from a v2-era TinyStorageDrivers writer.

The archived source is kept outside build output at
`<tinybox-repository>/.epic-repositories/legacy-tinybox-v0140`. From a TinyBox
checkout, reproduce the archive and its exact TinyBus gitlink with:

```sh
repo_root=$(git rev-parse --show-toplevel)
archive="$repo_root/.epic-repositories/legacy-tinybox-v0140"
fixture="$repo_root/crates/tinybox-bin/tests/fixtures/legacy-v0.1.40"
mkdir -p "$archive" "$archive/vendor"
git archive v0.1.40 | tar -x -C "$archive"
git clone --no-checkout https://github.com/tinyhumansai/tinybus "$archive/vendor/tinybus"
git -C "$archive/vendor/tinybus" fetch --depth=1 origin 1f33d1be1901a2d44bfe674cd7cf294cf3848821
git -C "$archive/vendor/tinybus" checkout --detach 1f33d1be1901a2d44bfe674cd7cf294cf3848821
mkdir -p "$archive/crates/tinybox-cli/examples"
cp "$fixture/write_storage_fixture.rs" "$archive/crates/tinybox-cli/examples/"
```

The example is implicitly discovered; the archived manifests and lockfile are
left byte-for-byte unchanged. Then run from the archived source root:

```sh
repo_root=$(git rev-parse --show-toplevel)
archive="$repo_root/.epic-repositories/legacy-tinybox-v0140"
fixture="$repo_root/crates/tinybox-bin/tests/fixtures/legacy-v0.1.40"
cd "$archive"
cargo run --locked -p tinybox-cli --example write_storage_fixture -- "$fixture/generated"
cp "$fixture/generated/boxes.json" "$fixture/boxes.json"
cp "$fixture/generated/templates.json" "$fixture/templates.json"
```

Copy the generated `boxes.json` and `templates.json` back into this fixture
directory. The old writer also creates an empty lockfile, which is not an
imported state file. The checked-in artifact hashes are:

- `boxes.json`: `cd23719baea2a659678ae54faf81dcd89ed03b00f7df919f075380073ac67d0f`
- `templates.json`: `008ef00e5dffef74f98366dd9d1d406dc17e60ea5b87abb9dc956c3bbf17819d`
