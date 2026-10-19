# Repository Guidelines

This file is the single source of truth for how humans and coding agents work
in this repository. `CLAUDE.md` is a symlink to this file, so every agent reads
the same instructions.

This repository is a Rust 2024 Cargo **workspace** implementing tinybox, a
workspace containerization runtime. See
[`docs/specs/tinybox-runtime.md`](docs/specs/tinybox-runtime.md) for the model
and [`ROADMAP.md`](ROADMAP.md) for what is built and what is next.

## Project Structure

```text
crates/
├── tinybox-core/            # the model, provider traits, and policy
│   ├── src/lib.rs           # crate docs + the entire public re-export surface
│   ├── src/error/           # crate-wide `Error` and `Result<T>`
│   ├── src/identity/        # validated BoxId, SnapshotId, HostRef, SandboxRef
│   ├── src/capability/      # SandboxCapabilities, IsolationLevel, SnapshotSupport
│   ├── src/spec/            # BoxSpec, Placement, Resources, Lifecycle
│   ├── src/runtime/         # the Host and Sandbox traits
│   ├── src/passthrough/     # the sandbox that confines nothing
│   ├── src/store/           # the Store trait and an in-memory one
│   ├── tests/               # integration tests against the public API only
│   └── examples/
├── tinybox-host/            # reach: the local machine
├── tinybox-docker/          # confinement: containers, snapshots, forking
├── tinybox-linux/           # confinement: rootless namespaces, no daemon
├── tinybox-microvm/         # confinement: a Firecracker guest with its own kernel
├── tinybox-ssh/             # reach: another machine, over SSH
├── tinybox-sync/            # fingerprinting and workspace transfer
├── tinybox-drivers/         # box records + jail index on the tinystoragedrivers ports (unpublished)
├── tinybox-cli/             # the `tinybox` binary
└── tinybox-module/          # cdylib, TinyBus ABI v1  ->  libtinybox.so
    ├── src/lib.rs           # crate docs; the adapter itself is private
    ├── src/tinybus_module/  # bus interface, setup, and ABI exports
    └── examples/            # verify_module, verify_github_release
vendor/tinybus/              # pinned TinyBus host types and module SDK
docs/
├── specs/                   # behavior and architecture specifications
├── plans/                   # test-first implementation plans
└── adr/                     # immutable architecture decision records
```

## Scope: tinybox only sandboxes

tinybox accepts a plan, enforces it, and reports events. It never decides what
is allowed: approval, audit decisions, redaction and command classification
belong to `tinysecurity`. A backend that cannot enforce a requested constraint
refuses with `Unsupported`/`ConstraintNotEnforced` or reports `BestEffort`; it
never degrades silently. Contract 2.0 removes TinyBox's command classifier,
executor list, and environment guard. `tinybox_core::shell::scan` remains only
for generic shell structure parsing; it makes no policy decisions.

Every crate the spec names now exists. Do not scaffold an empty one; that is a
placeholder.

Each feature area is a directory module under a crate's `src/`. A module root
explains the module, wires its pieces together, and exposes the smallest useful
API. Move substantial type definitions into `types.rs` and put module-local
unit tests in a sibling `<module>_tests.rs`, wired from the bottom of the module root
with:

```rust
#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
```

Do not write inline `mod tests` blocks in implementation files, do not name a test
file `test.rs`, `tests.rs` or `<module>_test.rs`, and do not
let a general-purpose `utils.rs` or `helpers.rs` grow — those are a symptom of a
missing module. Prefer many small modules that each do one thing well over few
broad ones.

Keep public exports centralized in each crate's `src/lib.rs`. Put shared error
variants in `tinybox-core`'s `src/error/mod.rs` and return the crate-wide
`Result<T>` from fallible public APIs.

## Two rules specific to this runtime

1. **A backend never emulates a capability it has not declared.** Every
   `Sandbox` returns a `SandboxCapabilities`; core checks it and returns
   `Error::Unsupported`. Approximating a capability — copying a filesystem
   because real forking is unavailable, or running a bare process where
   isolation was requested — is the one failure mode that silently converts
   "contained" into "not contained". Add a capability and declare it, or return
   the error.
2. **Reach and confinement stay orthogonal.** `Host` answers which machine,
   `Sandbox` answers what confines the process. Do not add a backend that
   merges the two (`DockerOverSsh` and its relatives); compose a `Placement`
   instead. See ADR 0002.
3. **A backend that drives an external tool runs it through its `Host`**, never
   through a native protocol client bound to a local socket. That is what keeps
   rule 2 true in practice, and it keeps command construction pure and
   testable. See ADR 0004.
4. **Adding a field to a stored type needs `#[serde(default)]`.** `BoxSpec`,
   `BoxInfo`, and `ExecRequest` are written to a user's box store; a field
   without a default makes an older store unreadable and orphans every box in
   it. Think about what the default *means*, too — `BoxInfo::created_at`
   defaults to `None` rather than the epoch, because "unknown age" must not read
   as "ancient" to the reaper.
5. **Time comes from a `Clock`, never `SystemTime::now`.** A test that waits an
   hour for a box to expire is not a test anyone will run.

## Build And Test

Run every command from the repository root. These four are the contract; CI
runs exactly them, so a green local run should mean a green CI run.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all-targets --all-features
cargo test --all-features
```

Supporting commands:

- `cargo fmt --all` — format before committing.
- `cargo test <filter>` — run a focused subset while iterating.
- `cargo run -p tinybox-core --example basic` — run the bundled example.
- `cargo build --release -p tinybox-module --lib` — build the installable
  cdylib. A virtual workspace needs the explicit `-p`.
- `cargo doc --no-deps --all-features` — build the rustdoc CI also builds with
  `RUSTDOCFLAGS="-D warnings"`.
- `cargo test --doc` — run doctests alone when editing documentation examples.

Never skip, ignore, or delete a failing test to make a command pass. Fix the
root cause, or stop and report the blocker.

## Coding Style

Use standard `rustfmt` output and Rust 2024 idioms. Do not hand-format around
`rustfmt`, and do not add `#[rustfmt::skip]` without a comment explaining why.

- `snake_case` for modules, files, functions, methods, fields, and locals.
- `PascalCase` for types, traits, and enum variants; `SCREAMING_SNAKE_CASE` for
  constants and statics.
- Name things for what they are, not for their layer: `RetryPolicy`, not
  `RetryHelper`.
- Prefer small, typed APIs over stringly-typed ones. Accept `&str` and generic
  `impl Into<String>` at boundaries; return owned, concrete types.
- Keep the public surface minimal: default to private, and export deliberately
  from `src/lib.rs`.
- `unsafe` is forbidden across the workspace by `[workspace.lints]` in the root
  `Cargo.toml`, which every crate inherits with `[lints] workspace = true`.
  **No crate relaxes it.** ADR 0003 reserved `tinybox-linux` as the one that
  might; ADR 0005 records why it did not need to. If you find yourself wanting
  `unsafe`, check first whether an existing tool already does the dangerous part
  correctly — that is how the namespace backend avoided it.

### Errors

- One workspace-wide `Error` enum in `crates/tinybox-core/src/error/mod.rs`,
  built with `thiserror`.
- Fallible public functions return `Result<T>`, the crate alias.
- Add a specific variant instead of stuffing context into a string; error
  messages are lowercase, without trailing punctuation.
- Do not `unwrap()`, `expect()`, or `panic!` anywhere the lints reach, which is
  every target — library, tests, examples, and benches alike. Examples return
  `Result` from `main`; tests return `Result` and use `?`. See the Testing
  section for how to assert a failure without panicking.
- Document a `# Errors` section on every public fallible function and a
  `# Panics` section on anything that can panic.

### Dependencies

Adding a dependency is a design decision. Before adding one, check whether the
standard library or an existing dependency already covers the need. When you do
add one:

- pin a caret range (`serde = "1"`), not an exact version;
- enable only the features you need, with `default-features = false` when that
  meaningfully trims the tree;
- gate anything optional behind a Cargo feature, documented in `Cargo.toml`;
- leave a comment above the entry explaining *why* the crate is needed and what
  uses it — see the existing entries for the expected tone;
- prefer well-maintained crates with a compatible license.

Keep `Cargo.lock` committed; this crate ships a lockfile so CI and releases are
reproducible.

### Vendored dependencies

TinyBus is registered as the `vendor/tinybus` git submodule and pinned by its
gitlink. It supplies the host types and module-side SDK required to build this
crate's `cdylib`. Initialize it after cloning with:

```sh
git submodule update --init --recursive
```

Do not edit vendored code from the parent repository. Make TinyBus changes in
its own repository, push them there, then update this repository's gitlink in a
separate commit. Keep the exact path dependencies and minimal features unless a
new module capability requires more.

## Testing

- Module-local unit tests live in `crates/<crate>/src/<feature>/mod_tests.rs` and may
  touch private items.
- `unwrap_used`, `expect_used`, and `panic` are denied in **test** targets too.
  Return `Result` from a test and use `?` for paths that should succeed; assert
  failures with `.err()` against an expected variant, or `assert!(matches!(..))`.
- Integration tests live in `tests/` and exercise only the public API — they are
  the regression suite for the crate's contract.
- Use descriptive, behavioral test names: `rejects_an_empty_name`, not
  `test_greet_2`.
- Cover the failure paths, not just the happy path. Every new error variant
  needs a test that produces it.
- For async behavior, standardize on one runtime (`tokio` as a dev-dependency
  for tests) rather than mixing runtimes.
- Tests must be deterministic and independent of network, wall-clock time, and
  execution order. Gate any live/network test behind a feature or an env var and
  name it `live_*` so it is easy to exclude.
- Maintain at least 90% line coverage in every source file **individually** —
  the gate is per file, not aggregate, and it is the dominant cost on new code.
  Keep impure I/O behind a narrow injectable trait so the logic around it is
  unit-testable without a live daemon. Add or update tests
  with every behavior change, and note any deliberately untested edge case in
  the pull request description.

Write the test first when fixing a bug: a failing test that reproduces the
report, then the fix that turns it green.

## Documentation

Write documentation for the reader who has never seen the code.

- Every public item gets a rustdoc comment. `missing_docs` is a warning that CI
  treats as an error.
- Start every `mod.rs` and `*_tests.rs` with a concise module-level `//!`
  description.
- `src/lib.rs` carries the crate-level overview: what the crate does, the
  primary entry points, and a short runnable example.
- Prefer concrete examples over vague description. Doc examples are compiled and
  run by `cargo test`, so they cannot drift.
- Complex modules must include a module-level `README.md` covering their design,
  public surface, and important operational constraints.
- Keep `README.md`, `docs/`, and module docs aligned with code changes in the
  same commit that changes behavior.
- Write accepted behavior and constraints in `docs/specs/` before creating a
  linked, implementation-ordered plan in `docs/plans/`. Specs define what and
  why; plans define how and in what sequence.
- Keep every Markdown file, including this one, at 500 lines or fewer. When a
  topic outgrows that, split it into focused files and link them from the
  nearest `README.md`.

## Git Workflow

- Never commit directly to `main`. Branch first, one branch per logical change.
- Do feature work in a git worktree so the main checkout stays clean.
- Commit subjects are concise and imperative: `Add retry policy to the client`.
  Keep the subject specific to the change and under ~72 characters.
- Make small, focused commits. Each commit should cover one logical change,
  build independently, and avoid mixing formatting, refactors, and behavior
  changes unless they are inseparable.
- Never commit secrets. `.env` is git-ignored; document new variables in
  `.env.example` with placeholder values.
- Never force-push a shared branch, rewrite published history, or bypass hooks
  with `--no-verify`.

## Pull Requests

Open pull requests ready for review, not as drafts, unless the work genuinely
must not merge yet. A pull request should:

- summarize what changed and why, in a few sentences;
- call out public API or behavior changes explicitly, or state "None";
- list the validation commands actually run, with their outcome;
- link the related issue;
- include updated tests, docs, and examples in the same change.

The template in `.github/PULL_REQUEST_TEMPLATE.md` encodes this checklist.
Address review feedback by fixing it, and reply on each thread describing what
changed. Do not resolve a thread whose feedback you have not addressed or
explicitly declined with a reason.

## Releases

Releases use the canonical TinyHumans shared workflow. Update the package
versions and matching local dependency constraints in a PR, regenerate the
lockfiles, and merge only after the required shared CI checks pass. For a
workspace using version.workspace, change its root workspace.package version.

Create and push a vX.Y.Z tag at the merged commit, or dispatch Release with
an existing tag input. The workflow checks that the tagged commit is on main
and that its module version matches the tag. It builds and verifies all 17
native and distro archives before publishing the immutable GitHub release.
Release never commits or pushes version bumps to main.

Follow semantic versioning: breaking changes require a major bump, or a minor
bump before 1.0. The module must remain packageable for every release target.

## Agent Working Agreement

For automated contributors specifically:

1. **Read before writing.** Inspect the surrounding module and match its
   conventions, comment density, and idiom rather than importing a house style.
2. **Verify, do not assume.** Run the four contract commands and read their
   output before reporting a task complete. Report failures with the output;
   never claim a check passed that you did not run.
3. **Stay in scope.** Implement what was asked. Do not opportunistically
   refactor, reformat, upgrade dependencies, or "fix" unrelated code — raise it
   instead.
4. **No placeholders in delivered code.** No `todo!()`, no stubbed functions, no
   commented-out alternatives left behind. If something cannot be finished, say
   so explicitly.
5. **Do not weaken the guardrails.** Never add blanket `#[allow(...)]`, relax a
   lint, mark a test `#[ignore]`, or loosen CI to get a green run. Fix the
   cause.
6. **Secrets stay out.** Never read, echo, or commit `.env` contents, tokens, or
   credentials, and never paste them into a pull request or issue.
7. **Ask only when blocked.** Make routine judgment calls yourself; escalate
   only irreversible decisions or genuine forks with no clear default.

## Tests live in `*_tests.rs` files

- Unit tests are never inline. Do not write a `#[cfg(test)] mod tests { ... }`
  block in a source file. Put the tests in a sibling `<module>_tests.rs`
  (`mod_tests.rs` beside a `mod.rs`, `lib_tests.rs` beside `lib.rs`) and declare
  it at the bottom of the module:

  ```rust
  #[cfg(test)]
  #[path = "foo_tests.rs"]
  mod tests;
  ```

- The test file starts with `use super::*;` and carries no `#[cfg(test)]` of its
  own. It is still a child module, so it reaches private items exactly as an
  inline module did.
- Name test files `<module>_tests.rs`; a second group for the same module is
  `<module>_<topic>_tests.rs`. Never `test.rs`, `tests.rs` or `<module>_test.rs`.
- Integration tests stay in the crate's `tests/` directory.
- OpenHuman's `scripts/externalize-inline-tests.mjs <repo-root> --write` moves
  inline test modules out mechanically; without `--write` it only reports.
