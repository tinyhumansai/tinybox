//! The tinybox `TinyBus` module.
//!
//! This crate is the bus adapter and nothing else: it exposes the model and
//! provider contract from [`tinybox_core`] over `TinyBus` and exports the ABI
//! v1 symbols the host's dynamic loader looks for. Keeping it thin is
//! deliberate — the CLI and the module are both adapters over the same core,
//! so behavior added here would be unavailable to the other.
//!
//! The compiled `cdylib` is named `libtinybox.so` (`.dylib` / `.dll` on other
//! platforms) rather than after the package, because that is the artifact name
//! the release workflow packages and the module allowlist records.
//!
//! # Interface
//!
//! The module serves `ai.tinyhumans.tinybox.Box` at
//! `/ai/tinyhumans/tinybox/Box`. `Describe` reports the crate version and the
//! sandboxes this build can construct; as backend crates land they are
//! registered there and begin appearing in that answer.
//!
//! # Trust
//!
//! `TinyBus` modules are trusted in-process code with the host's full
//! address-space privileges. tinybox exists to give a host somewhere to put
//! code it does *not* trust, so nothing here should be read as confining the
//! module itself.
//!
//! # Layout
//!
//! The bus adapter lives in a private `tinybus_module` module rather than at
//! the crate root, which keeps the ABI symbols `module_export!` generates out
//! of the public rustdoc surface.

mod tinybus_module;
