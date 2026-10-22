# Contract 1.21: interactive jailed stdio

Contract 1.21 appends six members to `METHODS`: `StartStdio`, `WriteStdio`,
`ReadStdio`, `CloseStdin`, `KillStdio` and `StdioStatus`. They let a host run a
long-lived child (a stdio MCP server) with piped stdin, stdout and stderr
streamed over the bus.

## Isolation

`StdioStartRequest.jail` is a required `NativeJailConfig`. The module applies
the `StartJailedExec` preflight before it consumes the reservation or spawns:
the backend must be available and not `noop`, must meet the requested
enforcement, and must meet the process-isolation floor when
`require_process_isolation` is set. `deny_read` is honoured as in 1.20. There is
no unconfined variant of this member; a host that trusts a server runs it
through its own path.

## Lifecycle

- `StartStdio` needs a `Process(resource)` reservation and a local passthrough
  directory resource. A retry of the identical request is idempotent.
- `WriteStdio` accepts at most `MAX_STDIO_WRITE_BYTES` and returns once the bytes
  are written. A closed or broken stdin answers `StdioClosed`.
- `ReadStdio` returns up to `MAX_STDIO_READ_BYTES` across both streams, waiting
  at most `MAX_STDIO_WAIT_MS`. Each stream buffers `MAX_STDIO_BUFFER_BYTES`;
  beyond that the pipe is not read, so the child blocks and no byte is lost.
- `CloseStdin` closes the pipe. `StdioStatus` reports `running` and the exit
  (`code` or `signal`).
- `KillStdio` kills the process group, waits for the reap and releases the
  handle. Resource `Close` and `Shutdown` do the same for every stdio process.
- At most `MAX_STDIO_PROCESSES` run per module instance.

The environment is a safe snapshot of the module's own (`PATH`, `HOME`, `TERM`,
`LANG`, `LC_ALL`, `LC_CTYPE`, `USER`, `SHELL`, `TMPDIR`) plus the request's
`env`; nothing else of the module's environment reaches the child.

Contract 1.22 adds optional native jail resource limits. A host must bind to a
module that advertises contract 1.22 before sending that field; see
[`contract-1-22.md`](contract-1-22.md).
