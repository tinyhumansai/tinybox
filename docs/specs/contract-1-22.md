# Contract 1.22: native jail resource limits

Contract 1.22 adds the optional `resources` member to `NativeJailConfig`. It
uses the existing `tinybox_bus::ResourceLimits` type:

```json
{
  "cpu_millis": 500,
  "memory_bytes": 1048576,
  "pids_max": 32,
  "disk_bytes": 10485760
}
```

The fields and units match the `Create` request's resource vocabulary. When
omitted, a request retains the behavior of contract 1.21. When supplied, all
four values must be positive and each corresponding hard constraint must pass
backend preflight, including when the request uses declared enforcement for
filesystem, network, or subprocess policy.

Hosts must bind only to a module advertising contract 1.22 before sending the
new field. Older modules may ignore unknown JSON fields, so sending it without
the compatibility check can silently lose the requested limits. The native
jail currently enforces none of these resource controls; it refuses a request
containing limits before process startup. This addition does not claim to
enforce native CPU, memory, process or disk limits.

Contract 1.22 is also the final one-release deprecation window for TinyBox's
legacy command-policy vocabulary: `AnalyzeCommand`, `CommandClass` and its
classification fields, executor/environment-guard signals, and
`AnalyzeShell.hidden_execution`. TinySecurity owns command policy. Hosts must
not use these legacy results to make policy decisions and should use
TinySecurity's policy contract instead. The next contract major removes this
policy vocabulary while retaining generic shell structure parsing and shell
transport helpers. Hosts must reject a module with a different contract major;
there is no silent compatibility fallback.
