# Docker egress enforcement

`NativeLinuxDockerEgressController` is the opt-in implementation of
`DockerEgressController`. `DockerSandbox` has no controller by default, so an
allowlist remains Unsupported unless a host installs this implementation.

The TinyBus module installs it per `Create`: a Docker box that asks for an
allowlist runs `NativeLinuxDockerEgressController::detect` first, resolving
names with `SystemEgressResolver`. A host that passes gets the controller for
that box, and its teardown. Any other host refuses the allowlist with
`Error::EgressAllowlistUnavailable`, naming the check it failed. Boxes with any
other network policy never run detection and keep using the host's configured
Docker daemon.

## Setup and enforcement

Before creating a network, the controller requires an explicitly local host,
the rootful Docker Engine socket accessible directly to the calling user,
Linux Docker, and non-interactive `sudo` access without a password or
`requiretty` for `iptables` and `ip6tables`. Docker's `DOCKER-USER` forwarding
hooks and a usable bridge firewall interface are also required. The controller
resolves hostnames once through the injected resolver, rejects loopback and
metadata answers, and retains every pinned address. Docker-assigned IPAM
subnets are checked before the firewall is installed; any pinned address
inside one causes the whole setup to roll back. Docker commands use the
explicit local rootful socket through `--host`; the request environment stays
intact so Docker can inherit explicitly requested workload variables through
its bare `--env KEY` arguments.

The controller installs a per-attempt bridge and default-drop input and forwarding
chains before Docker starts the workload. A fresh random attempt token is stored
on the Docker network and incorporated into the chain names. Pinned TCP destination addresses and
ports are accepted in `DOCKER-USER`; new host-bound traffic is dropped. The
input chain permits IPv6 Neighbor Solicitation and Advertisement for neighbor
discovery, plus established replies. Docker receives static `/etc/hosts` mappings for approved names and a
loopback-only resolver, so its embedded resolver cannot forward arbitrary
queries. Firewall rules also block loopback and the known metadata endpoints.

Each chain is created exclusively, then receives a cryptographic owner marker.
Cleanup first verifies the network owner, scope, and attempt labels and all
existing chain markers before changing firewall state. After a process restart,
an unmarked chain is reclaimable only when its attempt token matches the
network, the chain is empty, and no firewall hook references it. Nonempty or
otherwise ambiguous orphan chains are left untouched and cleanup fails closed.
The controller removes only the hooks, chains, and network owned by this
attempt. If verification or cleanup fails, the caller retains the box record so
cleanup can be retried.

## Public surface and limits

- `DockerEgressController` is the lifecycle interface consumed by
  `DockerSandbox`.
- `PreparedEgressNetwork` carries the Docker network name and pinned host
  mappings used in the workload's Docker arguments.
- `NativeLinuxDockerEgressController::new` accepts the resolver used to build
  the pinned plan.

Docker Desktop, remote or unknown daemons, rootless Docker, Windows, macOS, and
hosts without the required firewall capability are refused. The
controller filters TCP egress only; this is not a general-purpose firewall or
a claim that DNS answers are monitored after the one-time plan is created.
The real firewall proof runs only in the disposable hosted Ubuntu Docker job.
