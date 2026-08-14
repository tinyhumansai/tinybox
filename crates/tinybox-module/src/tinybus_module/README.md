# TinyBus module adapter

The bus-facing half of tinybox. It exposes the model in `tinybox-core` over
TinyBus and exports the ABI v1 symbols the host's dynamic loader looks for.

## Public surface

The module claims `ai.tinyhumans.tinybox.Box` and serves the object at
`/ai/tinyhumans/tinybox/Box`.

| Method | Arguments | Returns |
| --- | --- | --- |
| `Describe` | none | `String` — crate version, registered sandboxes, and which of them clear the untrusted-code isolation floor |

`registered_sandboxes` is empty until backend crates land. `Describe` reports
`sandboxes: none` rather than omitting the field, because a caller reading an
absent list cannot tell "no backends" from "the field was dropped".

## Design

This module is deliberately thin. The CLI and this adapter are both adapters
over `tinybox-core`, so behavior implemented here would be unavailable to the
other. Anything beyond translating bus calls belongs in core.

It is a **private** module rather than the crate root. `module_export!`
generates three `#[unsafe(no_mangle)]` items, and at the crate root those become
publicly reachable and trip `missing_docs`. Keeping them private is also
honest — they are an ABI, not an API anyone should call from Rust.

`describe` takes the sandbox list as a parameter instead of reading it. That
makes the rendering a pure function testable against a populated registry today,
before any backend exists to populate one.

## Constraints

- The manifest's `methods = [...]` list must match the `#[tinybus::interface]`
  dispatch table. `declared_methods_match_the_dispatch_table` asserts this;
  a mismatch means the host advertises a method that does not resolve.
- The `cdylib` is named `tinybox`, not after the package. `release.yml` reads
  that target name out of `cargo metadata`, so the released file stays
  `libtinybox.so` — do not rename `[lib] name` without updating the workflow.
- Do not retain Rust-owned data across the ABI boundary, and do not bypass the
  SDK exports with ad hoc FFI.
- Each module owns its own Tokio runtime, sized by `worker_threads` in the
  manifest. Borrowing the host's runtime is incorrect: a statically linked
  cdylib has its own Tokio thread-locals.
- `setup` returning `Ok(())` means *ready*, not *done*. The SDK then calls
  `host.ready()` and parks, keeping the connection and object tree alive.

## Trust

TinyBus modules are trusted in-process code with the host's full address-space
privileges. tinybox exists to give a host somewhere to put code it does *not*
trust; nothing here confines the module itself.
