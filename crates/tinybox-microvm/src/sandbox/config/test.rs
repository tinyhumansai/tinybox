//! Tests for the Firecracker invocation.

use tinybox_core::Resources;

use super::{memory_mib, vcpus};

#[test]
fn a_cpu_allowance_becomes_whole_vcpus() {
    // A VM gets whole CPUs; there is no fractional vCPU to hand out. Rounding
    // up rather than down means a caller never gets less than they asked for.
    assert_eq!(vcpus(1_000), 1);
    assert_eq!(vcpus(1_500), 2);
    assert_eq!(vcpus(2_000), 2);
    assert_eq!(vcpus(4_500), 5);
}

#[test]
fn a_machine_always_gets_at_least_one_cpu() {
    // Firecracker refuses a machine with none, and a caller asking for a
    // tenth of a core wants some CPU rather than an error.
    assert_eq!(vcpus(0), 1);
    assert_eq!(vcpus(1), 1);
    assert_eq!(vcpus(100), 1);
}

#[test]
fn memory_is_converted_to_mebibytes() {
    assert_eq!(memory_mib(512 * 1024 * 1024), 512);
    assert_eq!(memory_mib(2 * 1024 * 1024 * 1024), 2048);
    assert_eq!(memory_mib(Resources::DEFAULT.memory_bytes), 2048);
}

#[test]
fn a_machine_always_gets_at_least_a_mebibyte() {
    // Rounding a sub-mebibyte request to zero would produce a VM that cannot
    // boot, with no indication why.
    assert_eq!(memory_mib(1), 1);
    assert_eq!(memory_mib(0), 1);
}
