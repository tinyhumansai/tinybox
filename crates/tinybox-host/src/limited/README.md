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

LocalHost keeps its existing unbounded API. LimitedLocalHost starts a separate
Unix process group for every collected or managed command. Cleanup sends SIGKILL
to that group, waits for the direct child to be reaped, and then waits up to five
seconds for the group to stop executing. Linux checks live group members through
/proc, excluding exited zombies; their parent or operating-system init reaps them.
Other Unix systems wait until the kernel no longer reports the group. Cleanup
failure is explicit and never acknowledged as success. A process deliberately
escaping its group is outside this trusted passthrough ownership mechanism;
process groups provide lifecycle tracking, not a sandbox or isolation boundary.
Windows supervision needs a job-object owner and is explicitly unsupported here.

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
