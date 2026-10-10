# Bounded local collection

LimitedLocalHost shares LocalHost command construction but supervises each child
on the owning Tokio runtime. A caller dropping its future drops a cancellation
sender; the supervisor kills and awaits the child before decrementing its active
count. `drain` waits for those supervisors, including cancelled callers.

Stdout and stderr are read concurrently in fixed-size chunks. They reserve from
one atomic byte budget before extending their buffers, so the combined output
cannot grow beyond the configured cap. Overflow is an explicit
OutputLimitExceeded error, and kills/awaits the child. Standard input writing
runs concurrently with both readers to avoid pipe-buffer deadlocks.

LocalHost keeps its existing unbounded API. Both collectors configure child
kill-on-drop as a final guard. LimitedLocalHost supervises the direct child;
backends own their sandbox-wide cleanup, including descendants inside a box.
