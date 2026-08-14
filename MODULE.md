# tinybox TinyBus Module

This package contains the native `tinybox` module for TinyBus module ABI v1.
Install only the archive matching the host operating system and architecture.

The module claims `ai.tinyhumans.tinybox.Box`, serves the object at
`/ai/tinyhumans/tinybox/Box`, and provides the `Describe` method. `Describe`
takes no arguments and returns a summary of this build: the crate version, the
sandbox backends compiled into it, and which of those are strong enough for code
the operator does not trust.

The archive contains one `.so`, `.dylib`, or `.dll` plus `modules.toml`. Keep
those files together when copying them into a TinyBus module directory. The
allowlist binds the native library filename to its SHA-256 digest so TinyBus can
reject a missing, renamed, or modified artifact before initialization.

The GitHub release also publishes `checksum.toml` as a separate asset. TinyBus
checks that manifest before downloading and extracting the selected platform
archive. Install directly from a tagged release with:

```sh
tinybus modules load-github \
  https://github.com/tinyhumansai/tinybox/releases/tag/v0.1.5 \
  tinybox-0.1.5-ubuntu-24.04-x86_64.tar.gz \
  <archive-sha256>
```

## Trust

TinyBus modules are trusted in-process code with the host's full address-space
privileges. Install release artifacts only from a trusted source, and restart
the host after replacing a loaded module.

That applies to this module as much as any other. tinybox exists to give a host
somewhere to put code it does *not* trust — the boxes it creates — and nothing
about installing it confines the module itself.
