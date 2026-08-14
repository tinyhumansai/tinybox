# 6. A microVM boots an initramfs, not a disk image

- **Status:** Accepted
- **Date:** 2026-08-14

## Context

The microVM backend runs a command inside a Firecracker guest — a real kernel on
KVM, which is the only isolation tinybox offers that a kernel exploit cannot
cross. Getting a workspace and a command into that guest, and output back out,
needs a design, and the obvious one is the one every VM tool uses: build a root
filesystem image, attach it as a block device, boot into it, and talk to a guest
agent over vsock.

That design is what the plan anticipated for M7. Building it means a filesystem
image per box, a partition of some size chosen in advance, an agent binary to
write and version, a vsock protocol to define, and a way to read modified files
back out of an image the guest has unmounted. Each piece is small; together they
are most of the milestone, and none of it can be tested without a hypervisor.

There is a second option. A Linux kernel can be handed a cpio archive as an
initramfs and will unpack it into a tmpfs and run `/init` from it, with no block
device involved at all. The archive can hold a static busybox, a generated
`init`, and the workspace. The command travels on the kernel command line and
the output comes back on the serial console — both of which Firecracker already
plumbs, because they are how a kernel boots.

## Decision

Boot an initramfs. No drives, no network interfaces, no guest agent, no vsock.

- The **initramfs** is built in memory by `cpio/`, a hand-written `newc` writer.
  The format is a 110-byte ASCII header per entry and four-byte alignment;
  writing it out avoids materializing the guest tree on disk and depending on
  `cpio(1)` being installed.
- The **command** crosses as base64 in a single `tinybox_cmd=` value on the
  kernel command line. The kernel splits its command line on whitespace and does
  no quoting, so a shell command written literally would be torn apart at the
  first space — and an argument containing `tinybox_cmd=` could displace the real
  one. Base64 is one word from an alphabet with no shell meaning.
- The **output** comes back on `ttyS0`, bracketed by `TINYBOX-BEGIN` and
  `TINYBOX-EXIT:<status>` so it can be separated from the kernel's boot log.
- The guest's `init` ends with `reboot -f`, not `poweroff -f`.

## Consequences

- **A boot is fast.** The measured cost of creating a machine, running a
  command, and tearing it down is a few hundred milliseconds, against a
  hand-built guest. There is no image to build, no filesystem to make, and
  nothing to clean up afterwards but a temporary directory.
- **`reboot -f` versus `poweroff -f` is worth stating plainly**, because it was
  a 60-second hang before it was a design decision. Halting parks the vCPU and
  leaves the hypervisor waiting forever; a reset — with `reboot=k` on the
  command line — is an event Firecracker observes and exits on. The first
  working version of this backend took 60,065 ms per boot. The same code with
  one word changed takes 805 ms.
- **Nothing the guest writes comes back.** The whole filesystem is memory that
  is discarded when the machine resets. This is a real limit, not an oversight,
  and `live_nothing_the_guest_writes_comes_back` asserts it so it cannot quietly
  change. A backend that needs writes to persist needs a disk, and adding one
  later does not invalidate anything here.
- **The workspace must fit in the guest's memory**, because it *is* the guest's
  memory. That suits the workload — a command against a checkout — and rules out
  the backend for a large dataset.
- **The command line is bounded.** An x86 kernel accepts 2048 bytes and silently
  truncates beyond it, which would run a prefix of the intended command.
  `guest::cmdline` refuses instead, because a truncated command is worse than a
  failed one.
- **Almost all of it is testable without KVM.** The archive writer, the command
  encoding, the guest script, the console parser, and the Firecracker
  configuration are pure functions over bytes, covered by 48 unit tests. The 13
  tests that need a hypervisor are gated behind `TINYBOX_LIVE_MICROVM` and prove
  only what a real boot can: that the pieces fit.
- **The backend declares no snapshot support.** Firecracker's snapshot/restore
  is the reason to reach for a VMM at scale, and it is not built here. What
  `SnapshotSupport::None` buys is that nothing pretends otherwise.
- **Three artifacts must exist on the host**: `firecracker`, a static `busybox`,
  and an uncompressed kernel. tinybox downloads none of them. Booting whatever
  kernel happened to be in `/boot` would be a surprising thing to do on
  somebody's behalf, and most distribution kernels are compressed in a format
  Firecracker cannot read.
