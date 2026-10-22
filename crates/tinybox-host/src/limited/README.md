# Bounded local collection

LimitedLocalHost shares LocalHost command construction but supervises each child
on the owning Tokio runtime. A caller dropping its future drops a cancellation
sender; the supervisor kills and awaits the child before decrementing its active
count. `drain` waits for those supervisors, including cancelled callers.
The module uses `drain_checked`, which retains and reports native cleanup errors
even when the original execution waiter has gone away. Failed native cleanup
retains the child and process group for a later checked drain retry.

Stdout and stderr are read concurrently in fixed-size chunks. They reserve from
one atomic byte budget before extending their buffers, so the combined output
cannot grow beyond the configured cap. Overflow is an explicit
OutputLimitExceeded error, and kills/awaits the child. Standard input writing
runs concurrently with both readers to avoid pipe-buffer deadlocks.

Collection ends when the command has exited and both pipes have ended. A
process the command started in the background can keep the pipes open after
the command exits (a daemon that inherits stdout), and waiting for their end
would wait for that process. So once the command exits, the pipes get
`OUTPUT_DRAIN_GRACE` (3 s) to end; after that the output read so far is
returned with a note on stderr saying a process still holds the output.
Cleanup then retires the command's process group as usual. Both the plain and
the jailed collector use the same `collect_until_exit`.

LocalHost keeps its existing unbounded API. On Unix, LimitedLocalHost starts a
separate process group for every collected or managed command. Cleanup sends
SIGKILL to that group, waits for the direct child to be reaped, and then waits up
to five seconds for the group to stop executing. Linux checks live group members
through /proc, excluding exited zombies; their parent or operating-system init
reaps them. Other Unix systems inspect process group IDs and states with /bin/ps,
also excluding zombies. The probe runs asynchronously within the cleanup deadline
and is killed on cancellation; an expired probe is killed and reaped. Solaris and
illumos use the s state field; Darwin and BSD systems use stat. A permission error from SIGKILL is accepted only when a fresh process
table confirms there are no live members; otherwise cleanup remains failed.
JailLocalHost applies the same fresh process-table check when a jailed group
exits before SIGKILL; live members or a failed probe keep cleanup unacknowledged.
On Windows, every command starts in a Job Object and cleanup terminates and waits
for the whole job. Cleanup failure is explicit and never acknowledged as success.
An escaped Unix process group is outside this trusted passthrough ownership
mechanism; groups and Job Objects provide lifecycle tracking, not a sandbox or
isolation boundary.

ManagedProcess owns detached native work with discarded stdout/stderr. Its stop
method cooperatively cancels and joins its supervisor. Drop only requests cleanup;
call stop or the module Shutdown barrier before unloading the runtime. Natural
completion also terminates residual group members. Standard input is written
concurrently so a blocked write remains cancellable. The module never uses legacy
pid-file detach helpers for operations claiming acknowledged cleanup.

Command completion errors are independent of cleanup errors. Managed stop reports
a command error once after successful cleanup; is_cleaned lets owners release
the handle immediately. Native cleanup failures retain ownership and can be
retried. A supervisor panic cannot prove cleanup and remains an explicit failure.
