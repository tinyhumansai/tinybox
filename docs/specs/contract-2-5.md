# TinyBox contract 2.5

Contract 2.5 adds one optional field to `NativeJailConfig` and a `Default` for
it, without changing any 2.4 request or reply shape:

| Addition | What a host may rely on |
| --- | --- |
| `NativeJailConfig.deny_read_names` | `Vec<String>`, empty and omitted by default. File or directory names the child may neither read nor write wherever they appear, where `deny_read` takes exact paths. Only a backend that denies by name (Seatbelt, through a regex rule) admits a request carrying any; every other backend refuses it with `UNSUPPORTED_OPERATION` rather than ignoring it. |
| `impl Default for NativeJailConfig` | The most restrictive request: no grants, no network, no child processes, `Enforced`, the process-isolation floor required, no denials or limits. A host that builds requests with `..NativeJailConfig::default()` keeps compiling when the contract adds a field. |

- Each name is one path component: not empty, not `.` or `..`, at most
  `MAX_FILE_PATH_BYTES`, and without `/`, `\`, `"` or NUL. Anything else is
  refused with `INVALID_FILE_PATH`. Names count against `MAX_NATIVE_JAIL_GRANTS`
  together with the grants and path denials.
- Seatbelt denies `/<name>` and everything below it, as the profile's last
  rule, so it holds even inside a writable grant carved out of a path denial.
- The `JailBackend::denies_by_name` trait method (default `false`) is what a
  backend overrides to accept them. The `tinybox_jail` spawn helpers refuse a
  jail carrying names on a backend that returns `false`.

A 2.5 host refuses a 2.4 module, as for every minor: the module must advertise
the members the host may send.
