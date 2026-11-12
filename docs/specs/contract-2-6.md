# TinyBox contract 2.6

Contract 2.6 makes one field optional, without changing any other 2.5 request
or reply shape:

| Change | What a host may rely on |
| --- | --- |
| `ResourceLimits.disk_bytes` | `Option<u64>`, `None` by default, omitted on the wire when `None`. A value sent by an older host still decodes as `Some`. |

No backend enforces a writable disk budget, so the 8 GiB default was a number
nothing applied:

- On `Create`, a box's resources stay soft unless the caller lists them as
  hard requirements, and an unset `disk_bytes` keeps the core default
  (`Resources::DEFAULT`).
- On a native jail, `NativeJailConfig.resources` remains a hard request for
  CPU, memory and pids, and asks for `Disk` only when `disk_bytes` is set.
  Before 2.6 every such request carried a disk budget and was refused by every
  backend; without one it now reaches backends able to hold the other three.

A 2.6 host refuses a 2.5 module, as for every minor. That matters here: a
module before 2.6 fails to decode a `ResourceLimits` without `disk_bytes`, so a
host must have bound a 2.6 module before it sends one.
