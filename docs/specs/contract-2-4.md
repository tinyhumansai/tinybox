# TinyBox contract 2.4

Contract 2.4 adds one optional field to `ai.tinyhumans.tinybox.Box`'s `Create`
request, without changing any 2.3 request or reply shape:

| Addition | What a host may rely on |
| --- | --- |
| `CreateRequest.retention` | `Option<Retention>`, absent by default. A backend that supports it keeps the box for its owner across uses; every other backend refuses the `Create` with a backend error rather than running a disposable box. Only `agent37` supports it. |

```text
Retention { key: String, idle_sleep_secs: u32, delete_after_secs: u64 }
```

- `key` is an opaque, stable identifier the host chooses for the box's owner:
  1 to 128 characters of `[A-Za-z0-9_-]`. A later `Create` with the same key
  finds the same box again, including after the host process restarts, so a
  host must not let one owner choose another's key.
- `idle_sleep_secs` is how long the box may sit idle before it falls asleep.
  The backend clamps it to what its service accepts (agent37: 300 to 86400).
- `delete_after_secs` is how long a box may stay asleep before it is deleted.
  It must be greater than zero; zero would read as "delete as soon as it
  sleeps" and is refused.

For example, `Retention { key: "user-42", idle_sleep_secs: 900,
delete_after_secs: 2_592_000 }` sleeps after 15 idle minutes and is deleted after
30 days asleep.

A retained box falls asleep when idle and wakes on the next command. It ends
only by expiry: `Close` (and so a host shutting down or dropping an idle
handle) forgets the local record and leaves the box, and its files, in place.

In `tinybox-core` the same shape is `tinybox_core::Retention`, carried as
`BoxSpec::retention` (`#[serde(default)]`, so stored specs written earlier still
load) and declared by a sandbox as `Capability::Retention`. `BoxSpec::validate`
checks the key and delay; every backend that cannot retain calls
`BoxSpec::refuse_retention` from `create` and returns
`Error::Unsupported { capability: Retention, .. }`.

The box record in the module's store carries `retention` too (omitted when
unset, so the stored body of every other box is unchanged), which is what lets a
retained box survive a store round trip.

A host that needs retention requires `contract_version >= (2, 4)`. A module
that reports 2.3 or lower does not know the field and would ignore it, so a
host must check the version before sending it.

## agent37

With `retention` set, the `agent37` backend:

1. creates the instance with `auto_sleep: true`, `idle_timeout_seconds` clamped
   to 300..=86400, and metadata `tinybox.key=<key>` (the owner key);
2. on every retained `Create`, first lists the workspace's instances and
   - **adopts** the oldest (by `created`) instance whose `tinybox.key` equals
     the key and whose status can run commands (running, sleeping, or still
     provisioning/starting/waking), recording it locally and returning it
     instead of creating another;
   - **deletes** instances that have a `tinybox.key` entry, are `sleeping`, and
     whose `slept_at` is older than `now - delete_after_secs`, never the one
     being adopted, at most 20 per pass. A failed delete is ignored;
   - never touches an instance without a `tinybox.key` entry: the workspace may
     be shared with other things;
3. fails the `Create` when the listing fails, instead of creating a second box
   for an owner whose first one is merely unreachable.

The expiry rule uses the owner's `delete_after_secs` for every retained
instance it sees, so hosts sharing a workspace should agree on one value.
