//! Unit tests for the pasta private network: the closed-down flags, the
//! `/proc` parsing, and the failure paths that need no `pasta`.

use super::*;

#[test]
fn pasta_is_only_ever_started_with_forwarding_and_the_gateway_closed() {
    let args = PASTA_ARGS.join(" ");
    for required in [
        "--no-map-gw",
        "-T none",
        "-U none",
        "--dns-forward 169.254.1.1",
    ] {
        assert!(args.contains(required), "missing {required} in {args}");
    }
    // Nothing that would open a path back to the host.
    for forbidden in [
        "-t",
        "-u",
        "--map-host-loopback",
        "--map-guest-addr",
        "auto",
    ] {
        assert!(
            !PASTA_ARGS.contains(&forbidden),
            "{forbidden} must never be passed: {args}"
        );
    }
}

#[test]
fn the_jail_resolver_is_the_forwarded_address_only() {
    assert_eq!(resolv_conf(), "nameserver 169.254.1.1\n");
}

#[test]
fn pasta_and_nsenter_come_only_from_trusted_paths() {
    let found = Pasta::find(|path| {
        path == Path::new("/usr/bin/pasta") || path == Path::new("/usr/bin/nsenter")
    });
    assert_eq!(
        found,
        Some(Pasta {
            program: "/usr/bin/pasta".into(),
            nsenter: "/usr/bin/nsenter".into(),
        })
    );
    assert_eq!(
        found.as_ref().map(Pasta::nsenter),
        Some(Path::new("/usr/bin/nsenter"))
    );
    // Either one missing means no private network.
    assert!(Pasta::find(|path| path.ends_with("pasta")).is_none());
    assert!(Pasta::find(|path| path.ends_with("nsenter")).is_none());
}

#[test]
fn proc_listings_are_parsed() {
    assert_eq!(first_pid("4182 4190 \n"), Some(4182));
    assert_eq!(first_pid(""), None);
    assert_eq!(first_pid("x"), None);
    assert_eq!(
        parent_pid("Name:\tsh\nState:\tS\nPPid:\t4181\nTracerPid:\t0\n"),
        Some(4181)
    );
    assert_eq!(parent_pid("Name:\tsh\n"), None);
}

#[test]
fn only_a_default_route_counts_as_the_network_being_up() {
    let header = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n";
    let link = "eth0\t0000010A\t00000000\t0001\t0\t0\t100\t00F0FFFF\n";
    let default = "eth0\t00000000\t0100010A\t0003\t0\t0\t100\t00000000\n";
    assert!(!default_route(header));
    assert!(!default_route(&format!("{header}{link}")));
    assert!(default_route(&format!("{header}{link}{default}")));
    // The header line never counts, whatever it says.
    assert!(!default_route("x\t00000000\n"));
}

#[test]
fn waiting_reports_a_timeout_with_a_clear_error() {
    let error = wait_for(Instant::now(), || None::<()>).err();
    assert_eq!(
        error.as_ref().map(io::Error::kind),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(
        error.is_some_and(|e| e
            .to_string()
            .contains("did not bring up the jail's network")),
        "the error names what failed"
    );
    assert_eq!(wait_for(Instant::now(), || Some(7)).ok(), Some(7));
}

#[test]
fn a_pid_that_is_not_pastas_child_is_refused() -> io::Result<()> {
    // This process is not a child of pid 1's first child, nor of pid 1 here.
    let me = std::process::id();
    let error = open_namespaces(1, me).err();
    assert_eq!(error.map(|e| e.kind()), Some(io::ErrorKind::InvalidData));
    // A real parent/child pair whose namespace is this process's own is
    // refused too: the holder must have a network of its own.
    let mut child = Command::new("sleep").arg("5").spawn()?;
    let refused = open_namespaces(me, child.id()).err();
    child.kill()?;
    child.wait()?;
    assert_eq!(refused.map(|e| e.kind()), Some(io::ErrorKind::InvalidData));
    Ok(())
}

#[test]
fn a_fake_network_hands_out_duplicates_and_releases_without_a_process() -> io::Result<()> {
    let (_reader, writer) = io::pipe()?;
    let network = Network::fake(
        File::open("/proc/self/ns/user")?,
        File::open("/proc/self/ns/net")?,
        writer.into(),
    );
    assert!(network.pasta_pid().is_err());
    let (user, net, _writer) = network.descriptors()?;
    let own = std::fs::metadata("/proc/self/ns/net")?;
    let dup = File::from(net).metadata()?;
    assert_eq!((dup.dev(), dup.ino()), (own.dev(), own.ino()));
    drop(user);
    network.release();
    Ok(())
}

#[test]
fn an_unstarted_network_has_no_descriptors() {
    let network = Network {
        pasta: None,
        user: None,
        net: None,
        writer: None,
    };
    assert!(network.descriptors().is_err());
}
