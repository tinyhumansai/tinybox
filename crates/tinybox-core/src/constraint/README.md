# Constraint preflight

The public model separates individual security boundaries from lifecycle
capabilities. `ConstraintSupport::NONE` is the conservative declaration.
Backends add only enforced or best-effort behavior they actually implement.
`plan_check` is diagnostic and performs no execution; `require` rejects every
requested boundary except `Enforced`, returning a typed error. Setup failures
must still propagate from the backend rather than degrading to passthrough.

The model is used by the object-safe `Sandbox` trait and by `tinybox-jail`.
See [the specification](../../../../docs/specs/constraint-preflight.md) for
backend limitations and the meaning of each hard requirement.
