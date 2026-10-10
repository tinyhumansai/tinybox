//! Per-constraint preflight, independent of coarse lifecycle capabilities.
//!
//! A declaration describes implemented enforcement, not merely a configurable
//! knob. Callers must still handle setup failures. Best-effort support is never
//! accepted as a hard requirement. Unknown backends default to unsupported.

/// A security boundary requested before starting a workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Constraint {
    /// Confine filesystem reads and writes to the granted paths.
    Filesystem,
    /// Deny external network access.
    Network,
    /// Cap CPU consumption.
    Cpu,
    /// Cap resident memory.
    Memory,
    /// Cap total processes and threads.
    Pids,
    /// Cap writable disk usage.
    Disk,
    /// Forbid creating child processes.
    Subprocess,
}

impl Constraint {
    /// All modeled constraints, in diagnostic order.
    pub const ALL: [Self; 7] = [
        Self::Filesystem,
        Self::Network,
        Self::Cpu,
        Self::Memory,
        Self::Pids,
        Self::Disk,
        Self::Subprocess,
    ];
    const fn index(self) -> usize {
        self as usize
    }
}

impl std::fmt::Display for Constraint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Filesystem => "filesystem",
            Self::Network => "network",
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Pids => "pids",
            Self::Disk => "disk",
            Self::Subprocess => "subprocess",
        })
    }
}

/// What a backend actually implements for one constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    /// No implementation, including unavailable platform mechanisms.
    Unsupported,
    /// Partial or advisory implementation, unsuitable for a hard requirement.
    BestEffort,
    /// Full implementation; failure to apply it must prevent execution.
    Enforced,
}

impl std::fmt::Display for Enforcement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unsupported => "unsupported",
            Self::BestEffort => "best effort",
            Self::Enforced => "enforced",
        })
    }
}

/// Independent enforcement declarations for all constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstraintSupport([Enforcement; 7]);
impl Default for ConstraintSupport {
    fn default() -> Self {
        Self::NONE
    }
}
impl ConstraintSupport {
    /// Conservative declaration for unknown and passthrough backends.
    pub const NONE: Self = Self([Enforcement::Unsupported; 7]);
    /// Declare the actual enforcement of one constraint.
    #[must_use]
    pub const fn with(mut self, constraint: Constraint, enforcement: Enforcement) -> Self {
        self.0[constraint.index()] = enforcement;
        self
    }
    /// Inspect an individual constraint.
    #[must_use]
    pub const fn enforcement(self, constraint: Constraint) -> Enforcement {
        self.0[constraint.index()]
    }
    /// Inspect all requested constraints without executing anything.
    #[must_use]
    pub fn plan_check(self, requested: &[Constraint]) -> PlanCheck {
        PlanCheck {
            constraints: requested
                .iter()
                .map(|c| (*c, self.enforcement(*c)))
                .collect(),
        }
    }
    /// Refuse the first hard constraint that is not fully enforced.
    ///
    /// # Errors
    /// Returns [`crate::Error::ConstraintNotEnforced`] for unsupported or
    /// best-effort constraints. No workload is started.
    pub fn require(self, backend: &str, requested: &[Constraint]) -> crate::Result<()> {
        for &constraint in requested {
            let enforcement = self.enforcement(constraint);
            if enforcement != Enforcement::Enforced {
                return Err(crate::Error::ConstraintNotEnforced {
                    sandbox: backend.to_owned(),
                    constraint,
                    enforcement,
                });
            }
        }
        Ok(())
    }
}

/// Preflight diagnostics, including best-effort and unsupported constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanCheck {
    /// Each requested constraint and its actual enforcement.
    pub constraints: Vec<(Constraint, Enforcement)>,
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
