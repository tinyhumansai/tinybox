//! Deterministic startup and cleanup races over an injected host.
use super::*;
use tinybox_core::{ExecOutput as NativeOutput, ExecRequest as NativeRequest, Host};

#[test]
fn sandbox_selection_and_spec_mapping_preserve_host_policy() -> Result<()> {
    let host: Arc<dyn Host> = Arc::new(SshArgumentHost::default());
    let store = Arc::new(MemoryStore::new());
    assert!(
        make_sandbox("passthrough", host.clone(), store.clone())?
            .local_sandbox
            .is_some()
    );
    assert!(
        make_sandbox("docker", host.clone(), store.clone())?
            .local_sandbox
            .is_none()
    );
    assert!(
        make_sandbox("namespace", host.clone(), store.clone())?
            .local_sandbox
            .is_none()
    );
    assert!(make_sandbox("unknown", host, store).is_err());

    for (policy, expected) in [
        (
            tinybox_bus::NetworkPolicy::Denied,
            tinybox_core::NetworkPolicy::Denied,
        ),
        (
            tinybox_bus::NetworkPolicy::Egress,
            tinybox_core::NetworkPolicy::Egress,
        ),
        (
            tinybox_bus::NetworkPolicy::Open,
            tinybox_core::NetworkPolicy::Open,
        ),
    ] {
        let request = CreateRequest {
            resource: ResourceId("spec-test".into()),
            backend: "docker".into(),
            host: HostConfig::Local,
            workspace: Workspace::Directory("/work".into()),
            network: policy,
            resources: tinybox_bus::ResourceLimits {
                cpu_millis: 1500,
                memory_bytes: 1_000_000,
                pids_max: 12,
                disk_bytes: 2_000_000,
            },
            ports: vec![tinybox_bus::PortMapping {
                guest: 8080,
                host: Some(18080),
            }],
            env: BTreeMap::from([("MODE".into(), "test".into())]),
        };
        let spec = make_spec(&request, "ssh")?;
        assert_eq!(spec.workspace.host.as_str(), "ssh");
        assert_eq!(spec.network, expected);
        assert_eq!(spec.resources.cpu_millis, 1500);
        assert_eq!(spec.resources.memory_bytes, 1_000_000);
        assert_eq!(spec.resources.pids_max, 12);
        assert_eq!(spec.resources.disk_bytes, 2_000_000);
        assert_eq!(spec.ports.len(), 1);
        assert_eq!(spec.env.get("MODE").map(String::as_str), Some("test"));
    }
    Ok(())
}

#[tokio::test]
async fn local_create_uses_the_production_host_selection_path() -> Result<()> {
    let resources = Resources::default();
    let id = resources.reserve(ReserveRequest::Resource).await?;
    let info = resources
        .create(CreateRequest {
            resource: id.clone(),
            backend: "passthrough".into(),
            workspace: Workspace::Directory(".".into()),
            ..Default::default()
        })
        .await?;
    assert_eq!(info.resource, id);
    assert_eq!(info.backend, "passthrough");
    resources.close(&info.resource).await?;
    Ok(())
}

#[derive(Debug)]
struct ForwardingDockerHost {
    opens: Arc<std::sync::atomic::AtomicUsize>,
    closes: Arc<std::sync::atomic::AtomicUsize>,
}

#[derive(Debug)]
struct CountForwardClose(Arc<std::sync::atomic::AtomicUsize>);

impl tinybox_core::ForwardGuard for CountForwardClose {
    fn close(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl Host for ForwardingDockerHost {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn run(&self, request: &NativeRequest) -> tinybox_core::Result<NativeOutput> {
        let output = if request
            .argv
            .iter()
            .any(|argument| argument.contains("NetworkSettings.Ports"))
        {
            br#"{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"38080"}]}"#.to_vec()
        } else if request
            .argv
            .iter()
            .any(|argument| argument.contains(".State.Status"))
        {
            b"running".to_vec()
        } else {
            Vec::new()
        };
        Ok(NativeOutput::new(0, output, Vec::new()))
    }

    async fn forward(
        &self,
        remote: std::net::SocketAddr,
    ) -> tinybox_core::Result<tinybox_core::Forward> {
        assert_eq!(remote, std::net::SocketAddr::from(([127, 0, 0, 1], 38080)));
        self.opens.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(tinybox_core::Forward::guarded(
            std::net::SocketAddr::from(([127, 0, 0, 1], 44000)),
            Box::new(CountForwardClose(self.closes.clone())),
        ))
    }
}

#[derive(Debug, Default)]
struct SshArgumentHost(std::sync::Mutex<Vec<String>>);

#[async_trait::async_trait]
impl Host for SshArgumentHost {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn run(&self, request: &NativeRequest) -> tinybox_core::Result<NativeOutput> {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = request.argv.clone();
        Ok(NativeOutput::new(0, Vec::new(), Vec::new()))
    }
}

#[derive(Debug, Default)]
struct RemoteProcessHost {
    commands: std::sync::Mutex<Vec<Vec<String>>>,
    stopped: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl Host for RemoteProcessHost {
    fn name(&self) -> &'static str {
        tinybox_ssh::NAME
    }

    async fn run(&self, request: &NativeRequest) -> tinybox_core::Result<NativeOutput> {
        let script = request.argv.last().map(String::as_str).unwrap_or_default();
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.argv.clone());
        if script.contains("kill -TERM") {
            self.stopped
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        let stdout = if script.contains("kill -0")
            && !self.stopped.load(std::sync::atomic::Ordering::SeqCst)
        {
            b"running".to_vec()
        } else if script.contains("kill -0") {
            b"gone".to_vec()
        } else {
            Vec::new()
        };
        Ok(NativeOutput::new(0, stdout, Vec::new()))
    }
}

#[tokio::test]
async fn remote_process_handle_stays_owned_until_the_module_stops_it() -> Result<()> {
    let host = Arc::new(RemoteProcessHost::default());
    let resources = Resources::default();
    let resource = resources.reserve(ReserveRequest::Resource).await?;
    resources
        .create_on(
            CreateRequest {
                resource: resource.clone(),
                backend: "passthrough".into(),
                workspace: Workspace::Directory(".".into()),
                ..Default::default()
            },
            host.clone(),
        )
        .await?;

    let process = resources
        .reserve(ReserveRequest::Process(resource.clone()))
        .await?;
    let started = resources
        .spawn(SpawnRequest {
            process: process.clone(),
            command: ExecRequest {
                resource: resource.clone(),
                argv: vec!["sleep".into(), "30".into()],
                cwd: None,
                env: BTreeMap::new(),
                stdin: None,
            },
        })
        .await?;
    assert_eq!(started.process, process);
    assert!(resources.is_running(&started).await?);
    resources.cancel(&started).await?;
    assert!(!resources.is_running(&started).await?);

    let calls = host
        .commands
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(
        calls.len() >= 3,
        "start, probe, and stop use the selected host"
    );
    assert!(calls[0].iter().any(|arg| arg == "-c"));
    assert!(
        calls
            .last()
            .is_some_and(|argv| { argv.iter().any(|arg| arg.contains("kill -TERM")) })
    );
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn ssh_host_config_uses_the_existing_cli_and_explicit_trust_policy() -> Result<()> {
    let inner = Arc::new(SshArgumentHost::default());
    let host = configured_host(
        &HostConfig::Ssh(tinybox_bus::SshHostConfig {
            destination: "operator@example.test".into(),
            port: Some(2222),
            identity: Some("/tmp/test-identity".into()),
            known_hosts: Some("/tmp/test-known-hosts".into()),
            accept_new_host_key: true,
        }),
        inner.clone(),
    )?;
    host.run(&NativeRequest::new(["uname", "-s"]))
        .await
        .map_err(|error| backend_error(&error))?;

    let argv = inner
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(argv[0], "ssh");
    assert!(argv.windows(2).any(|args| args == ["-p", "2222"]));
    assert!(
        argv.windows(2)
            .any(|args| args == ["-i", "/tmp/test-identity"])
    );
    assert!(
        argv.iter()
            .any(|arg| arg == "UserKnownHostsFile=/tmp/test-known-hosts")
    );
    assert!(
        argv.iter()
            .any(|arg| arg == "StrictHostKeyChecking=accept-new")
    );
    assert!(argv.iter().any(|arg| arg == "operator@example.test"));

    let default_host = configured_host(
        &HostConfig::Ssh(tinybox_bus::SshHostConfig {
            destination: "review-host".into(),
            port: None,
            identity: None,
            known_hosts: None,
            accept_new_host_key: false,
        }),
        inner.clone(),
    )?;
    default_host
        .run(&NativeRequest::new(["true"]))
        .await
        .map_err(|error| backend_error(&error))?;
    let argv = inner
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(
        !argv
            .iter()
            .any(|arg| arg == "StrictHostKeyChecking=accept-new")
    );
    assert!(
        configured_host(
            &HostConfig::Ssh(tinybox_bus::SshHostConfig {
                destination: "-bad-option".into(),
                port: None,
                identity: None,
                known_hosts: None,
                accept_new_host_key: false,
            }),
            inner,
        )
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn published_port_forward_is_replayed_and_closed_with_its_owner() -> Result<()> {
    let opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let closes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let resources = Resources::default();
    let id = resources.reserve(ReserveRequest::Resource).await?;
    let created =
        create_forwarding_docker_resource(&resources, id.clone(), &opens, &closes).await?;
    assert_eq!(
        created.published_ports,
        [tinybox_bus::PublishedPort {
            guest: 8080,
            host: 38080
        }]
    );

    let first = resources
        .reserve(ReserveRequest::Forward(id.clone()))
        .await?;
    let request = ForwardRequest {
        resource: id.clone(),
        forward: first.clone(),
        guest_port: 8080,
    };
    let opened = resources.forward(request.clone()).await?;
    assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(opened.local_address, "127.0.0.1:44000");
    assert_eq!(resources.forward(request).await?, opened);
    assert!(
        resources
            .forward(ForwardRequest {
                resource: id.clone(),
                forward: first.clone(),
                guest_port: 8081,
            })
            .await
            .is_err(),
        "an opened handle cannot be rebound to a different guest port"
    );
    resources
        .close_forward(CloseForwardRequest {
            resource: id.clone(),
            forward: first.clone(),
        })
        .await?;
    resources
        .close_forward(CloseForwardRequest {
            resource: id.clone(),
            forward: first,
        })
        .await?;
    assert_eq!(closes.load(std::sync::atomic::Ordering::SeqCst), 1);

    let second = resources
        .reserve(ReserveRequest::Forward(id.clone()))
        .await?;
    resources
        .forward(ForwardRequest {
            resource: id.clone(),
            forward: second,
            guest_port: 8080,
        })
        .await?;
    resources.close(&id).await?;
    assert_eq!(closes.load(std::sync::atomic::Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn forward_replay_is_rejected_after_close_marks_the_resource_closing() -> Result<()> {
    let opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let closes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let resources = Resources::default();
    let id = resources.reserve(ReserveRequest::Resource).await?;
    create_forwarding_docker_resource(&resources, id.clone(), &opens, &closes).await?;
    let forward = resources
        .reserve(ReserveRequest::Forward(id.clone()))
        .await?;
    let request = ForwardRequest {
        resource: id.clone(),
        forward,
        guest_port: 8080,
    };
    resources.forward(request.clone()).await?;

    // This is the same lifecycle marker installed by Close and Shutdown. A
    // replay must not disclose an address once either operation has started.
    resources
        .executions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .closing
        .insert(id.clone());
    assert!(
        resources.forward(request).await.is_err(),
        "a replay must be rejected after close admission is frozen"
    );
    assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 1);
    resources.close(&id).await?;
    assert_eq!(closes.load(std::sync::atomic::Ordering::SeqCst), 1);
    Ok(())
}

#[derive(Debug)]
struct PendingForwardHost {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    opens: Arc<std::sync::atomic::AtomicUsize>,
    closes: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl Host for PendingForwardHost {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn run(&self, request: &NativeRequest) -> tinybox_core::Result<NativeOutput> {
        let output = if request
            .argv
            .iter()
            .any(|argument| argument.contains("NetworkSettings.Ports"))
        {
            br#"{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"38080"}]}"#.to_vec()
        } else if request
            .argv
            .iter()
            .any(|argument| argument.contains(".State.Status"))
        {
            b"running".to_vec()
        } else {
            Vec::new()
        };
        Ok(NativeOutput::new(0, output, Vec::new()))
    }

    async fn forward(
        &self,
        remote: std::net::SocketAddr,
    ) -> tinybox_core::Result<tinybox_core::Forward> {
        assert_eq!(remote, std::net::SocketAddr::from(([127, 0, 0, 1], 38080)));
        self.opens.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.entered.notify_one();
        self.release.notified().await;
        Ok(tinybox_core::Forward::guarded(
            std::net::SocketAddr::from(([127, 0, 0, 1], 44000)),
            Box::new(CountForwardClose(self.closes.clone())),
        ))
    }
}

async fn pending_forward_race(shutdown: bool) -> Result<()> {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let closes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let resources = Arc::new(Resources::default());
    let id = resources.reserve(ReserveRequest::Resource).await?;
    resources
        .create_on(
            CreateRequest {
                resource: id.clone(),
                backend: "docker".into(),
                workspace: Workspace::Image("mock".into()),
                network: tinybox_bus::NetworkPolicy::Open,
                ports: vec![tinybox_bus::PortMapping {
                    guest: 8080,
                    host: None,
                }],
                ..Default::default()
            },
            Arc::new(PendingForwardHost {
                entered: entered.clone(),
                release: release.clone(),
                opens: opens.clone(),
                closes: closes.clone(),
            }),
        )
        .await?;
    let forward = resources
        .reserve(ReserveRequest::Forward(id.clone()))
        .await?;
    let request = ForwardRequest {
        resource: id.clone(),
        forward,
        guest_port: 8080,
    };
    let runner = resources.clone();
    let pending = tokio::spawn(async move { runner.forward(request).await });
    entered.notified().await;

    let lifecycle_runner = resources.clone();
    let close_id = id.clone();
    let lifecycle = tokio::spawn(async move {
        if shutdown {
            lifecycle_runner.shutdown().await
        } else {
            lifecycle_runner.close(&close_id).await
        }
    });
    loop {
        let shutdown_marked = resources.state.lock().await.shutdown;
        let resource_closing = resources
            .executions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closing
            .contains(&id);
        if shutdown_marked || resource_closing {
            break;
        }
        tokio::task::yield_now().await;
    }
    release.notify_one();
    assert!(
        pending.await.map_err(Error::failed)?.is_err(),
        "a pending tunnel must not publish after Close or Shutdown marks it closed"
    );
    lifecycle.await.map_err(Error::failed)??;
    assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(closes.load(std::sync::atomic::Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn pending_forward_drops_its_tunnel_when_close_marks_resource_closing() -> Result<()> {
    pending_forward_race(false).await
}

#[tokio::test]
async fn pending_forward_drops_its_tunnel_when_shutdown_marks_module_closed() -> Result<()> {
    pending_forward_race(true).await
}

#[tokio::test]
async fn forward_rejects_wrong_resource_and_unpublished_port_before_opening() -> Result<()> {
    let opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let closes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let resources = Resources::default();
    let first = resources.reserve(ReserveRequest::Resource).await?;
    let second = resources.reserve(ReserveRequest::Resource).await?;
    create_forwarding_docker_resource(&resources, first.clone(), &opens, &closes).await?;
    create_forwarding_docker_resource(&resources, second.clone(), &opens, &closes).await?;
    let reservation = resources
        .reserve(ReserveRequest::Forward(first.clone()))
        .await?;

    assert!(
        resources
            .forward(ForwardRequest {
                resource: second.clone(),
                forward: reservation.clone(),
                guest_port: 8080,
            })
            .await
            .is_err(),
        "a reservation cannot start a forward for another resource"
    );
    assert!(
        resources
            .forward(ForwardRequest {
                resource: first.clone(),
                forward: reservation.clone(),
                guest_port: 9999,
            })
            .await
            .is_err(),
        "unpublished ports are refused without consuming the reservation"
    );
    assert!(
        resources
            .close_forward(CloseForwardRequest {
                resource: second.clone(),
                forward: reservation.clone(),
            })
            .await
            .is_err(),
        "a reservation cannot be closed through a different resource"
    );
    assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 0);
    resources
        .forward(ForwardRequest {
            resource: first.clone(),
            forward: reservation,
            guest_port: 8080,
        })
        .await?;
    assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 1);
    resources.close(&first).await?;
    resources.close(&second).await?;
    Ok(())
}

async fn create_forwarding_docker_resource(
    resources: &Resources,
    resource: ResourceId,
    opens: &Arc<std::sync::atomic::AtomicUsize>,
    closes: &Arc<std::sync::atomic::AtomicUsize>,
) -> Result<ResourceInfo> {
    let host = Arc::new(ForwardingDockerHost {
        opens: opens.clone(),
        closes: closes.clone(),
    });
    resources
        .create_on(
            CreateRequest {
                resource,
                backend: "docker".into(),
                workspace: Workspace::Image("mock".into()),
                network: tinybox_bus::NetworkPolicy::Open,
                ports: vec![tinybox_bus::PortMapping {
                    guest: 8080,
                    host: None,
                }],
                ..Default::default()
            },
            host,
        )
        .await
}

#[tokio::test]
async fn reservation_scope_expiry_sequence_and_pending_limits_fail_without_native_work()
-> Result<()> {
    let clock = Arc::new(tinybox_core::clock::FixedClock::at_epoch());
    let resources = Resources {
        clock: clock.clone(),
        ..Resources::default()
    };
    assert!(
        resources
            .reserve(ReserveRequest::Process(ResourceId("unknown".into())))
            .await
            .is_err()
    );
    let id = resources.reserve(ReserveRequest::Resource).await?;
    clock.advance(std::time::Duration::from_secs(
        tinybox_bus::RESERVATION_TTL_SECS,
    ));
    let request = |resource| CreateRequest {
        resource,
        backend: "passthrough".into(),
        workspace: Workspace::Directory(".".into()),
        env: BTreeMap::new(),
        ..Default::default()
    };
    assert!(resources.create(request(id)).await.is_err());
    let id = resources.reserve(ReserveRequest::Resource).await?;
    resources.create(request(id.clone())).await?;
    let token = resources
        .reserve(ReserveRequest::Process(id.clone()))
        .await?;
    assert!(resources.create(request(token.clone())).await.is_err());
    assert!(resources.close(&token).await.is_err());
    {
        let mut state = resources.state.lock().await;
        for index in 0..tinybox_bus::MAX_PROCESSES_PER_RESOURCE {
            state.pending_processes.insert(
                ResourceId(format!("queued-{index}")),
                (id.clone(), Arc::new(AtomicBool::new(false))),
            );
        }
    }
    assert!(
        resources
            .spawn(SpawnRequest {
                process: token,
                command: ExecRequest {
                    resource: id.clone(),
                    argv: vec!["must-not-start".into()],
                    cwd: None,
                    env: BTreeMap::new(),
                    stdin: None
                }
            })
            .await
            .is_err()
    );
    resources.state.lock().await.pending_processes.clear();
    resources.close(&id).await?;
    resources.state.lock().await.next = u64::MAX;
    assert!(resources.reserve(ReserveRequest::Resource).await.is_err());
    Ok(())
}

#[tokio::test]
async fn docker_exec_and_detached_processes_use_the_owned_sandbox_lifecycle() -> Result<()> {
    let resources = Resources::default();
    let host = Arc::new(DelayedHost::default());
    host.release.notify_one();
    let id = resources.reserve(ReserveRequest::Resource).await?;
    resources
        .create_on(
            CreateRequest {
                resource: id.clone(),
                backend: "docker".into(),
                workspace: Workspace::Image("mock".into()),
                env: BTreeMap::new(),
                ..Default::default()
            },
            host,
        )
        .await?;
    let slot = resources.slot(&id).await?;
    slot.lock()
        .await
        .as_mut()
        .ok_or_else(|| Error::failed("missing resource"))?
        .collector = Some(Arc::new(tinybox_host::LimitedLocalHost::new(100)));
    let command = ExecRequest {
        resource: id.clone(),
        argv: vec!["true".into()],
        cwd: None,
        env: BTreeMap::new(),
        stdin: None,
    };
    resources.exec(command.clone()).await?;
    let process = resources
        .spawn(SpawnRequest {
            process: resources
                .reserve(ReserveRequest::Process(id.clone()))
                .await?,
            command,
        })
        .await?;
    assert_eq!(process.resource, id);
    resources.cancel(&process).await?;
    resources.close(&id).await?;
    Ok(())
}

#[derive(Debug, Default)]
struct FailedDockerStopHost {
    exec_attempts: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl Host for FailedDockerStopHost {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn run(&self, request: &NativeRequest) -> tinybox_core::Result<NativeOutput> {
        match request.argv.get(1).map(String::as_str) {
            Some("exec") => {
                let attempt = self
                    .exec_attempts
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if attempt == 1 {
                    Ok(NativeOutput::new(
                        1,
                        Vec::new(),
                        b"process cleanup was refused".to_vec(),
                    ))
                } else {
                    Ok(NativeOutput::new(0, Vec::new(), Vec::new()))
                }
            }
            Some("inspect") => Ok(NativeOutput::new(0, b"running".to_vec(), Vec::new())),
            _ => Ok(NativeOutput::new(0, Vec::new(), Vec::new())),
        }
    }
}

#[tokio::test]
async fn docker_cancel_retains_process_when_stop_command_fails() -> Result<()> {
    let resources = Resources::default();
    let host = Arc::new(FailedDockerStopHost::default());
    let id = resources.reserve(ReserveRequest::Resource).await?;
    resources
        .create_on(
            CreateRequest {
                resource: id.clone(),
                backend: "docker".into(),
                workspace: Workspace::Image("mock".into()),
                env: BTreeMap::new(),
                ..Default::default()
            },
            host.clone(),
        )
        .await?;
    let process = resources
        .spawn(SpawnRequest {
            process: resources
                .reserve(ReserveRequest::Process(id.clone()))
                .await?,
            command: ExecRequest {
                resource: id.clone(),
                argv: vec!["sleep".into(), "30".into()],
                cwd: None,
                env: BTreeMap::new(),
                stdin: None,
            },
        })
        .await?;

    assert!(resources.cancel(&process).await.is_err());
    let slot = resources.slot(&id).await?;
    assert!(
        slot.lock()
            .await
            .as_ref()
            .is_some_and(|entry| entry.processes.contains_key(&process.process)),
        "failed Docker cleanup must keep the caller-known process handle"
    );
    resources.cancel(&process).await?;
    assert!(
        slot.lock()
            .await
            .as_ref()
            .is_some_and(|entry| !entry.processes.contains_key(&process.process)),
        "the process handle is released only after acknowledged cleanup"
    );
    resources.close(&id).await?;
    Ok(())
}

#[derive(Debug, Default)]
struct LostDockerSpawnReplyHost {
    exec_attempts: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl Host for LostDockerSpawnReplyHost {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn run(&self, request: &NativeRequest) -> tinybox_core::Result<NativeOutput> {
        match request.argv.get(1).map(String::as_str) {
            Some("exec") => {
                let attempt = self
                    .exec_attempts
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if attempt < 2 {
                    Err(tinybox_core::Error::Backend {
                        sandbox: "docker".into(),
                        operation: "execute command",
                        message: "reply lost after remote command may have started".into(),
                    })
                } else if request
                    .argv
                    .last()
                    .is_some_and(|script| script.contains("kill -0"))
                {
                    Ok(NativeOutput::new(0, b"running".to_vec(), Vec::new()))
                } else {
                    Ok(NativeOutput::new(0, Vec::new(), Vec::new()))
                }
            }
            Some("inspect") => Ok(NativeOutput::new(0, b"running".to_vec(), Vec::new())),
            _ => Ok(NativeOutput::new(0, Vec::new(), Vec::new())),
        }
    }
}

#[tokio::test]
async fn lost_docker_spawn_reply_keeps_reserved_handle_for_cleanup_retry() -> Result<()> {
    let resources = Resources::default();
    let host = Arc::new(LostDockerSpawnReplyHost::default());
    let id = resources.reserve(ReserveRequest::Resource).await?;
    resources
        .create_on(
            CreateRequest {
                resource: id.clone(),
                backend: "docker".into(),
                workspace: Workspace::Image("mock".into()),
                env: BTreeMap::new(),
                ..Default::default()
            },
            host.clone(),
        )
        .await?;
    let process_id = resources
        .reserve(ReserveRequest::Process(id.clone()))
        .await?;
    let started = resources
        .spawn(SpawnRequest {
            process: process_id.clone(),
            command: ExecRequest {
                resource: id.clone(),
                argv: vec!["sleep".into(), "30".into()],
                cwd: None,
                env: BTreeMap::new(),
                stdin: None,
            },
        })
        .await;
    assert!(
        started.is_err(),
        "the lost startup reply must reach the caller"
    );
    assert_eq!(
        host.exec_attempts.load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    let slot = resources.slot(&id).await?;
    assert!(
        slot.lock().await.as_ref().is_some_and(|entry| {
            entry
                .processes
                .get(&process_id)
                .is_some_and(OwnedProcess::is_running)
        }),
        "the consumed reservation remains a caller-known cleanup handle"
    );
    assert!(
        resources
            .is_running(&ProcessRef {
                resource: id.clone(),
                process: process_id.clone(),
            })
            .await?,
        "a retained Docker process is still queryable while cleanup is retryable"
    );
    resources
        .cancel(&ProcessRef {
            resource: id.clone(),
            process: process_id.clone(),
        })
        .await?;
    assert_eq!(
        host.exec_attempts.load(std::sync::atomic::Ordering::SeqCst),
        4
    );
    resources.close(&id).await?;
    Ok(())
}

#[derive(Debug, Default)]
struct LostDockerCreateReplyHost {
    commands: std::sync::Mutex<Vec<Vec<String>>>,
    rm_attempts: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl Host for LostDockerCreateReplyHost {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn run(&self, request: &NativeRequest) -> tinybox_core::Result<NativeOutput> {
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.argv.clone());
        match request.argv.get(1).map(String::as_str) {
            Some("run") => Err(tinybox_core::Error::Backend {
                sandbox: "docker".into(),
                operation: "run",
                message: "reply lost after container creation".into(),
            }),
            Some("rm") => {
                let attempt = self
                    .rm_attempts
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if attempt == 0 {
                    Ok(NativeOutput::new(
                        1,
                        Vec::new(),
                        b"daemon temporarily unavailable".to_vec(),
                    ))
                } else {
                    Ok(NativeOutput::new(0, Vec::new(), Vec::new()))
                }
            }
            Some("inspect")
                if request
                    .argv
                    .get(3)
                    .is_some_and(|format| format.contains("tinybox.attempt")) =>
            {
                let attempt = self
                    .commands
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .iter()
                    .rev()
                    .find_map(|command| {
                        command.windows(2).find_map(|pair| {
                            pair[0]
                                .eq("--label")
                                .then_some(pair[1].as_str())
                                .filter(|label| label.starts_with("ai.tinyhumans.tinybox.attempt="))
                        })
                    })
                    .and_then(|label| label.split_once('=').map(|(_, value)| value.to_owned()))
                    .unwrap_or_default();
                Ok(NativeOutput::new(0, attempt.into_bytes(), Vec::new()))
            }
            _ => Ok(NativeOutput::new(0, b"running".to_vec(), Vec::new())),
        }
    }
}

#[tokio::test]
async fn uncertain_docker_create_keeps_named_container_cleanup_retryable() -> Result<()> {
    let resources = Resources::default();
    let host = Arc::new(LostDockerCreateReplyHost::default());
    let id = resources.reserve(ReserveRequest::Resource).await?;
    let created = resources
        .create_on(
            CreateRequest {
                resource: id.clone(),
                backend: "docker".into(),
                workspace: Workspace::Image("mock-image".into()),
                env: BTreeMap::new(),
                ..Default::default()
            },
            host.clone(),
        )
        .await;

    assert!(
        created.is_err(),
        "the lost create reply must reach the caller"
    );
    assert_eq!(
        host.rm_attempts.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert!(
        resources.slot(&id).await.is_ok(),
        "module must retain cleanup ownership"
    );
    resources.close(&id).await?;
    assert_eq!(
        host.rm_attempts.load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    assert!(
        resources.slot(&id).await.is_err(),
        "successful retry releases the slot"
    );
    Ok(())
}

#[tokio::test]
async fn create_refuses_backends_missing_from_the_platform_before_owning_a_resource() -> Result<()>
{
    let resources = Resources::default();
    let host = Arc::new(DelayedHost::default());
    let resource = resources.reserve(ReserveRequest::Resource).await?;

    let error = resources
        .create_on_for_platform(
            CreateRequest {
                resource: resource.clone(),
                backend: "namespace".into(),
                workspace: Workspace::Directory(".".into()),
                env: BTreeMap::new(),
                ..Default::default()
            },
            host,
            super::super::Platform::Unix,
        )
        .await
        .err()
        .ok_or_else(|| Error::failed("the Linux namespace backend was available on macOS"))?;

    assert_eq!(error.wire_name(), tinybox_bus::UNSUPPORTED_BACKEND);
    assert!(
        resources.slot(&resource).await.is_err(),
        "a rejected backend must not leave a resource slot behind"
    );
    Ok(())
}

#[tokio::test]
async fn passthrough_create_on_an_unsupervised_platform_only_records_the_resource() -> Result<()> {
    let resources = Resources::default();
    let host = Arc::new(DelayedHost::default());
    let resource = resources.reserve(ReserveRequest::Resource).await?;

    let created = resources
        .create_on_for_platform(
            CreateRequest {
                resource: resource.clone(),
                backend: "passthrough".into(),
                workspace: Workspace::Directory(".".into()),
                env: BTreeMap::new(),
                ..Default::default()
            },
            host,
            super::super::Platform::Other,
        )
        .await?;

    assert_eq!(created.backend, "passthrough");
    assert_eq!(created.state, "ready");
    let slot = resources.slot(&resource).await?;
    slot.lock()
        .await
        .as_mut()
        .ok_or_else(|| Error::failed("missing resource"))?
        .collector = Some(Arc::new(tinybox_host::LimitedLocalHost::new(100)));
    let command = ExecRequest {
        resource: resource.clone(),
        argv: vec!["true".into()],
        cwd: None,
        env: BTreeMap::new(),
        stdin: None,
    };
    let Err(error) = resources.exec(command.clone()).await else {
        return Err(Error::failed(
            "execution must follow the advertised platform capability",
        ));
    };
    assert_eq!(error.wire_name(), tinybox_bus::UNSUPPORTED_OPERATION);
    let Err(error) = resources
        .spawn(SpawnRequest {
            process: resources
                .reserve(ReserveRequest::Process(resource.clone()))
                .await?,
            command,
        })
        .await
    else {
        return Err(Error::failed(
            "spawn must follow the advertised platform capability",
        ));
    };
    assert_eq!(error.wire_name(), tinybox_bus::UNSUPPORTED_OPERATION);
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn close_fences_process_reservations_before_waiting_for_resource_cleanup() -> Result<()> {
    let resources = Arc::new(Resources::default());
    let resource = resources.reserve(ReserveRequest::Resource).await?;
    resources
        .create(CreateRequest {
            resource: resource.clone(),
            backend: "passthrough".into(),
            workspace: Workspace::Directory(".".into()),
            env: BTreeMap::new(),
            ..Default::default()
        })
        .await?;
    let slot = resources.slot(&resource).await?;
    let held_slot = slot.lock().await;
    let closing_resources = resources.clone();
    let closing_resource = resource.clone();
    let closing = tokio::spawn(async move { closing_resources.close(&closing_resource).await });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if resources
                .executions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .closing
                .contains(&resource)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| Error::failed("close did not begin"))?;

    let reservation = resources
        .reserve(ReserveRequest::Process(resource.clone()))
        .await;
    drop(held_slot);
    closing.await.map_err(Error::failed)??;
    assert!(
        reservation.is_err(),
        "closing resources must reject new process reservations"
    );
    Ok(())
}

#[tokio::test]
async fn shutdown_waits_for_delayed_startups_and_prevents_late_publication() -> Result<()> {
    let resources = Arc::new(Resources::default());
    let host = Arc::new(DelayedHost::default());
    let id = resources.reserve(ReserveRequest::Resource).await?;
    let idle = resources.reserve(ReserveRequest::Resource).await?;
    let runner = resources.clone();
    let native_host = host.clone();
    let request = CreateRequest {
        resource: id.clone(),
        backend: "docker".into(),
        workspace: Workspace::Image("mock".into()),
        env: BTreeMap::new(),
        ..Default::default()
    };
    let creating = tokio::spawn(async move { runner.create_on(request, native_host).await });
    host.started.notified().await;
    let process = resources
        .reserve(ReserveRequest::Process(id.clone()))
        .await?;
    let runner = resources.clone();
    let spawning = tokio::spawn(async move {
        runner
            .spawn(SpawnRequest {
                process,
                command: ExecRequest {
                    resource: id,
                    argv: vec!["must-not-start".into()],
                    cwd: None,
                    env: BTreeMap::new(),
                    stdin: None,
                },
            })
            .await
    });
    while resources.state.lock().await.pending_processes.is_empty() {
        tokio::task::yield_now().await;
    }
    let runner = resources.clone();
    let shutdown = tokio::spawn(async move { runner.shutdown().await });
    while !resources.state.lock().await.shutdown {
        tokio::task::yield_now().await;
    }
    assert!(!shutdown.is_finished());
    assert!(resources.reserve(ReserveRequest::Resource).await.is_err());
    assert!(
        resources
            .create(CreateRequest {
                resource: idle,
                backend: "passthrough".into(),
                workspace: Workspace::Directory(".".into()),
                env: BTreeMap::new(),
                ..Default::default()
            })
            .await
            .is_err()
    );
    host.release.notify_one();
    assert!(creating.await.map_err(Error::failed)?.is_err());
    assert!(spawning.await.map_err(Error::failed)?.is_err());
    shutdown.await.map_err(Error::failed)??;
    assert!(host.destroyed.load(Ordering::SeqCst));
    let state = resources.state.lock().await;
    assert!(state.entries.is_empty());
    assert!(state.pending_processes.is_empty());
    assert!(state.reservations.is_empty());
    drop(state);
    resources.shutdown().await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn cancelling_a_queued_spawn_prevents_native_start_and_completed_slots_are_reclaimed()
-> Result<()> {
    let resources = Arc::new(Resources::default());
    let id = resources.reserve(ReserveRequest::Resource).await?;
    resources
        .create(CreateRequest {
            resource: id.clone(),
            backend: "passthrough".into(),
            workspace: Workspace::Directory(".".into()),
            env: BTreeMap::new(),
            ..Default::default()
        })
        .await?;
    let process = ProcessRef {
        resource: id.clone(),
        process: resources
            .reserve(ReserveRequest::Process(id.clone()))
            .await?,
    };
    let slot = resources.slot(&id).await?;
    let guard = slot.lock().await;
    let runner = resources.clone();
    let pending = process.clone();
    let spawning = tokio::spawn(async move {
        runner
            .spawn(SpawnRequest {
                process: pending.process,
                command: ExecRequest {
                    resource: pending.resource,
                    argv: vec!["must-not-start".into()],
                    cwd: None,
                    env: BTreeMap::new(),
                    stdin: None,
                },
            })
            .await
    });
    while resources.state.lock().await.pending_processes.is_empty() {
        tokio::task::yield_now().await;
    }
    let runner = resources.clone();
    let pending = process.clone();
    let cancelling = tokio::spawn(async move { runner.cancel(&pending).await });
    while !resources.state.lock().await.pending_processes[&process.process]
        .1
        .load(Ordering::SeqCst)
    {
        tokio::task::yield_now().await;
    }
    drop(guard);
    let error = spawning
        .await
        .map_err(Error::failed)?
        .err()
        .ok_or_else(|| Error::failed("startup was not cancelled"))?;
    assert_eq!(error.wire_name(), tinybox_bus::EXEC_CANCELLED);
    cancelling.await.map_err(Error::failed)??;
    for _ in 0..=tinybox_bus::MAX_PROCESSES_PER_RESOURCE {
        let request = SpawnRequest {
            process: resources
                .reserve(ReserveRequest::Process(id.clone()))
                .await?,
            command: ExecRequest {
                resource: id.clone(),
                argv: vec!["true".into()],
                cwd: None,
                env: BTreeMap::new(),
                stdin: None,
            },
        };
        let process = resources.spawn(request.clone()).await?;
        while resources.is_running(&process).await? {
            tokio::task::yield_now().await;
        }
        assert!(resources.spawn(request).await.is_err());
    }
    resources.shutdown().await?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn native_cancel_and_close_terminate_descendants_and_reap_direct_children() -> Result<()> {
    for mode in [
        "cancel",
        "close-detached",
        "close-dropped-exec",
        "shutdown",
        "shutdown-exec",
    ] {
        let directory = tempfile::tempdir().map_err(Error::failed)?;
        let ready = directory.path().join("pids");
        let resources = Arc::new(Resources::default());
        let resource = resources.reserve(ReserveRequest::Resource).await?;
        resources
            .create(CreateRequest {
                resource: resource.clone(),
                backend: "passthrough".into(),
                workspace: Workspace::Directory(".".into()),
                env: BTreeMap::new(),
                ..Default::default()
            })
            .await?;
        let script = format!(
            "sleep 600 & echo $$ $! > {}; wait",
            tinybox_core::shell::quote(&ready.to_string_lossy())
        );
        let command = ExecRequest {
            resource: resource.clone(),
            argv: vec!["sh".into(), "-c".into(), script],
            cwd: None,
            env: BTreeMap::new(),
            stdin: None,
        };
        let mut process = None;
        let mut waiter = None;
        if mode.ends_with("exec") {
            let runner = resources.clone();
            let native = tokio::spawn(async move { runner.exec(command).await });
            waiter = Some(tokio::spawn(super::super::finish_operation(native)));
        } else {
            process = Some(
                resources
                    .spawn(SpawnRequest {
                        process: resources
                            .reserve(ReserveRequest::Process(resource.clone()))
                            .await?,
                        command,
                    })
                    .await?,
            );
        }
        let pids = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Ok(contents) = std::fs::read_to_string(&ready)
                    && contents.split_whitespace().count() == 2
                {
                    break contents;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(Error::failed)?;
        if let Some(waiter) = waiter {
            waiter.abort();
            assert!(waiter.await.is_err());
        }
        if mode == "cancel" {
            resources
                .cancel(&process.ok_or_else(|| Error::failed("missing process"))?)
                .await?;
        } else if mode.starts_with("shutdown") {
            resources.shutdown().await?;
        } else {
            resources.close(&resource).await?;
        }
        for (index, pid) in pids.split_whitespace().enumerate() {
            let status = std::fs::read_to_string(format!("/proc/{pid}/status"));
            if index == 0 {
                assert!(status.is_err(), "direct workload child was not reaped");
            } else if let Ok(status) = status {
                assert!(
                    status
                        .lines()
                        .find(|line| line.starts_with("State:"))
                        .is_some_and(|line| line.contains("Z (zombie)")),
                    "descendant still executes after native cleanup"
                );
            }
        }
        if mode == "cancel" {
            resources.close(&resource).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn reservations_allow_reordered_acquisition_and_cleanup_only_the_selected_target()
-> Result<()> {
    let resources = Resources::default();
    let first = resources.reserve(ReserveRequest::Resource).await?;
    let retired = resources.reserve(ReserveRequest::Resource).await?;
    let last = resources.reserve(ReserveRequest::Resource).await?;
    resources.close(&retired).await?;
    let request = |resource| CreateRequest {
        resource,
        backend: "passthrough".into(),
        workspace: Workspace::Directory(".".into()),
        env: BTreeMap::new(),
        ..Default::default()
    };
    resources.create(request(last.clone())).await?;
    resources.create(request(first.clone())).await?;
    assert!(resources.create(request(retired)).await.is_err());
    let process = resources
        .reserve(ReserveRequest::Process(first.clone()))
        .await?;
    assert!(
        resources
            .cancel(&ProcessRef {
                resource: last.clone(),
                process: process.clone()
            })
            .await
            .is_err()
    );
    resources
        .cancel(&ProcessRef {
            resource: first.clone(),
            process: process.clone(),
        })
        .await?;
    assert!(
        resources
            .spawn(SpawnRequest {
                process,
                command: ExecRequest {
                    resource: first.clone(),
                    argv: vec!["unused".into()],
                    cwd: None,
                    env: BTreeMap::new(),
                    stdin: None
                }
            })
            .await
            .is_err()
    );
    resources.close(&first).await?;
    assert!(resources.create(request(first)).await.is_err());
    resources.close(&last).await?;
    assert!(resources.state.lock().await.reservations.is_empty());
    assert!(
        resources
            .executions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closing
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn repeated_create_close_reclaims_admission_beyond_the_old_lifetime_cap() -> Result<()> {
    let resources = Resources::default();
    for _ in 0..=tinybox_bus::MAX_RESERVATIONS {
        let resource = resources.reserve(ReserveRequest::Resource).await?;
        resources
            .create(CreateRequest {
                resource: resource.clone(),
                backend: "passthrough".into(),
                workspace: Workspace::Directory(".".into()),
                env: BTreeMap::new(),
                ..Default::default()
            })
            .await?;
        resources.close(&resource).await?;
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_processes_release_admission_beyond_the_old_retained_cap() -> Result<()> {
    let resources = Resources::default();
    let resource = resources.reserve(ReserveRequest::Resource).await?;
    resources
        .create(CreateRequest {
            resource: resource.clone(),
            backend: "passthrough".into(),
            workspace: Workspace::Directory(".".into()),
            env: BTreeMap::new(),
            ..Default::default()
        })
        .await?;
    for _ in 0..=tinybox_bus::MAX_PROCESSES_PER_RESOURCE {
        let process = resources
            .spawn(SpawnRequest {
                process: resources
                    .reserve(ReserveRequest::Process(resource.clone()))
                    .await?,
                command: ExecRequest {
                    resource: resource.clone(),
                    argv: vec!["true".into()],
                    cwd: None,
                    env: BTreeMap::new(),
                    stdin: None,
                },
            })
            .await?;
        resources.cancel(&process).await?;
    }
    resources.close(&resource).await?;
    Ok(())
}

#[derive(Debug, Default)]
struct DelayedHost {
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
    destroyed: std::sync::atomic::AtomicBool,
    exec_started: tokio::sync::Notify,
    exec_release: tokio::sync::Notify,
    exec_finished: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl Host for DelayedHost {
    fn name(&self) -> &'static str {
        "local"
    }
    async fn run(&self, request: &NativeRequest) -> tinybox_core::Result<NativeOutput> {
        if request.argv.get(1).is_some_and(|arg| arg == "run") {
            self.started.notify_one();
            self.release.notified().await;
        }
        if request.argv.get(1).is_some_and(|arg| arg == "exec")
            && request.argv.iter().any(|arg| arg == "mock-workload")
        {
            self.exec_started.notify_one();
            self.exec_release.notified().await;
            self.exec_finished
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        if request.argv.get(1).is_some_and(|arg| arg == "rm") {
            self.destroyed
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        let stdout = if request.argv.get(1).is_some_and(|arg| arg == "inspect") {
            b"running".to_vec()
        } else {
            Vec::new()
        };
        Ok(NativeOutput::new(0, stdout, Vec::new()))
    }
}

#[tokio::test]
async fn close_during_native_creation_destroys_the_eventual_resource() -> Result<()> {
    let resources = Arc::new(Resources::default());
    let host = Arc::new(DelayedHost::default());
    let id = resources.reserve(ReserveRequest::Resource).await?;
    let create_resources = resources.clone();
    let create_host = host.clone();
    let create_id = id.clone();
    let creating = tokio::spawn(async move {
        create_resources
            .create_on(
                CreateRequest {
                    resource: create_id,
                    backend: "docker".into(),
                    workspace: Workspace::Image("mock-image".into()),
                    env: BTreeMap::new(),
                    ..Default::default()
                },
                create_host,
            )
            .await
    });
    host.started.notified().await;
    let close_resources = resources.clone();
    let close_id = id.clone();
    let close_started = Arc::new(tokio::sync::Notify::new());
    let close_signal = close_started.clone();
    let closing = tokio::spawn(async move {
        close_signal.notify_one();
        close_resources.close(&close_id).await
    });
    close_started.notified().await;
    assert!(!closing.is_finished());
    assert!(!host.destroyed.load(std::sync::atomic::Ordering::SeqCst));
    host.release.notify_one();
    creating.await.map_err(Error::failed)??;
    closing.await.map_err(Error::failed)??;
    assert!(host.destroyed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(resources.inspect(&id).await.is_err());
    Ok(())
}

#[tokio::test]
async fn close_cancels_owned_native_execution_after_its_waiter_drops() -> Result<()> {
    let resources = Arc::new(Resources::default());
    let host = Arc::new(DelayedHost::default());
    let id = resources.reserve(ReserveRequest::Resource).await?;
    host.release.notify_one();
    resources
        .create_on(
            CreateRequest {
                resource: id.clone(),
                backend: "docker".into(),
                workspace: Workspace::Image("mock-image".into()),
                env: BTreeMap::new(),
                ..Default::default()
            },
            host.clone(),
        )
        .await?;
    let exec_resources = resources.clone();
    let request = ExecRequest {
        resource: id.clone(),
        argv: vec!["mock-workload".into()],
        cwd: None,
        env: BTreeMap::new(),
        stdin: None,
    };
    let native = tokio::spawn(async move { exec_resources.exec(request).await });
    let waiter = tokio::spawn(super::super::finish_operation(native));
    host.exec_started.notified().await;
    waiter.abort();
    assert!(waiter.await.is_err());
    let close_resources = resources.clone();
    let close_id = id.clone();
    let close_started = Arc::new(tokio::sync::Notify::new());
    let close_signal = close_started.clone();
    let closing = tokio::spawn(async move {
        close_signal.notify_one();
        close_resources.close(&close_id).await
    });
    close_started.notified().await;
    assert!(!host.exec_finished.load(std::sync::atomic::Ordering::SeqCst));
    closing.await.map_err(Error::failed)??;
    assert!(!host.exec_finished.load(std::sync::atomic::Ordering::SeqCst));
    assert!(host.destroyed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(resources.inspect(&id).await.is_err());
    Ok(())
}

#[tokio::test]
async fn idle_and_active_admission_are_bounded_and_expiry_never_reopens_ids() -> Result<()> {
    let clock = Arc::new(tinybox_core::clock::FixedClock::at_epoch());
    let resources = Resources {
        clock: clock.clone(),
        ..Resources::default()
    };
    let first = resources.reserve(ReserveRequest::Resource).await?;
    for _ in 1..tinybox_bus::MAX_RESERVATIONS {
        resources.reserve(ReserveRequest::Resource).await?;
    }
    assert!(resources.reserve(ReserveRequest::Resource).await.is_err());
    clock.advance(std::time::Duration::from_secs(
        tinybox_bus::RESERVATION_TTL_SECS,
    ));
    let next = resources.reserve(ReserveRequest::Resource).await?;
    assert_ne!(first, next);
    let request = |resource| CreateRequest {
        resource,
        backend: "passthrough".into(),
        workspace: Workspace::Directory(".".into()),
        env: BTreeMap::new(),
        ..Default::default()
    };
    assert!(resources.create(request(first)).await.is_err());
    for _ in 0..tinybox_bus::MAX_ACTIVE_RESOURCES {
        let id = resources.reserve(ReserveRequest::Resource).await?;
        resources.create(request(id)).await?;
    }
    assert!(resources.create(request(next)).await.is_err());
    let ids: Vec<_> = resources
        .state
        .lock()
        .await
        .entries
        .keys()
        .cloned()
        .collect();
    for id in ids {
        resources.close(&id).await?;
    }
    for invalid in [
        String::new(),
        "has space".into(),
        "../path".into(),
        "a".repeat(tinybox_bus::MAX_ID_BYTES + 1),
    ] {
        assert!(resources.close(&ResourceId(invalid)).await.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn a_pending_create_does_not_block_closing_another_resource() -> Result<()> {
    let resources = Arc::new(Resources::default());
    let ready = resources.reserve(ReserveRequest::Resource).await?;
    resources
        .create(CreateRequest {
            resource: ready.clone(),
            backend: "passthrough".into(),
            workspace: Workspace::Directory(".".into()),
            env: BTreeMap::new(),
            ..Default::default()
        })
        .await?;
    let host = Arc::new(DelayedHost::default());
    let pending_resources = resources.clone();
    let pending_host = host.clone();
    let pending = tokio::spawn(async move {
        pending_resources
            .create_on(
                CreateRequest {
                    resource: pending_resources.reserve(ReserveRequest::Resource).await?,
                    backend: "docker".into(),
                    workspace: Workspace::Image("mock".into()),
                    env: BTreeMap::new(),
                    ..Default::default()
                },
                pending_host,
            )
            .await
    });
    host.started.notified().await;
    resources.close(&ready).await?;
    assert!(!pending.is_finished());
    host.release.notify_one();
    let created = pending.await.map_err(Error::failed)??;
    resources.close(&created.resource).await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn process_admission_refuses_overflow_before_native_start() -> Result<()> {
    let resources = Resources::default();
    let id = resources.reserve(ReserveRequest::Resource).await?;
    resources
        .create(CreateRequest {
            resource: id.clone(),
            backend: "passthrough".into(),
            workspace: Workspace::Directory(".".into()),
            env: BTreeMap::new(),
            ..Default::default()
        })
        .await?;
    let mut processes = Vec::new();
    for _ in 0..tinybox_bus::MAX_PROCESSES_PER_RESOURCE {
        processes.push(
            resources
                .spawn(SpawnRequest {
                    process: resources
                        .reserve(ReserveRequest::Process(id.clone()))
                        .await?,
                    command: ExecRequest {
                        resource: id.clone(),
                        argv: vec!["sleep".into(), "600".into()],
                        cwd: None,
                        env: BTreeMap::new(),
                        stdin: None,
                    },
                })
                .await?,
        );
    }
    assert!(
        resources
            .spawn(SpawnRequest {
                process: resources
                    .reserve(ReserveRequest::Process(id.clone()))
                    .await?,
                command: ExecRequest {
                    resource: id.clone(),
                    argv: vec!["unused".into()],
                    cwd: None,
                    env: BTreeMap::new(),
                    stdin: None
                }
            })
            .await
            .is_err()
    );
    for process in processes {
        resources.cancel(&process).await?;
    }
    resources.close(&id).await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn close_reaps_a_running_native_exec_before_returning() -> Result<()> {
    let directory = tempfile::tempdir().map_err(Error::failed)?;
    let ready = directory.path().join("ready.pid");
    let resources = Arc::new(Resources::default());
    let id = resources.reserve(ReserveRequest::Resource).await?;
    resources
        .create(CreateRequest {
            resource: id.clone(),
            backend: "passthrough".into(),
            workspace: Workspace::Directory(".".into()),
            env: BTreeMap::new(),
            ..Default::default()
        })
        .await?;
    let runner = resources.clone();
    let script = format!(
        "echo $$ > {}; exec sleep 600",
        tinybox_core::shell::quote(&ready.to_string_lossy())
    );
    let command = ExecRequest {
        resource: id.clone(),
        argv: vec!["sh".into(), "-c".into(), script],
        cwd: None,
        env: BTreeMap::new(),
        stdin: None,
    };
    let running = tokio::spawn(async move { runner.exec(command).await });
    let pid = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(contents) = std::fs::read_to_string(&ready)
                && !contents.trim().is_empty()
            {
                return contents.trim().to_owned();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(Error::failed)?;
    resources.close(&id).await?;
    assert!(running.await.map_err(Error::failed)?.is_err());
    let probe = tinybox_host::LocalHost::new()
        .run(&NativeRequest::new(["kill", "-0", &pid]))
        .await
        .map_err(|error| backend_error(&error))?;
    assert!(!probe.succeeded());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn module_collection_enforces_output_cap_before_a_reply_is_allocated() -> Result<()> {
    let resources = Resources::default();
    let id = resources.reserve(ReserveRequest::Resource).await?;
    resources
        .create(CreateRequest {
            resource: id.clone(),
            backend: "passthrough".into(),
            workspace: Workspace::Directory(".".into()),
            env: BTreeMap::new(),
            ..Default::default()
        })
        .await?;
    let error = resources
        .exec(ExecRequest {
            resource: id.clone(),
            argv: vec!["yes".into(), "output".into()],
            cwd: None,
            env: BTreeMap::new(),
            stdin: None,
        })
        .await
        .err()
        .ok_or_else(|| Error::failed("expected output limit error"))?;
    assert_eq!(error.wire_name(), tinybox_bus::OUTPUT_LIMIT);
    assert!(resources.inspect(&id).await.is_ok());
    resources.close(&id).await?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn shutdown_drains_other_processes_and_resources_after_a_process_failure() -> Result<()> {
    let resources = Resources::default();
    let directory = tempfile::tempdir().map_err(Error::failed)?;
    let mut ids = Vec::new();
    for _ in 0..2 {
        let id = resources.reserve(ReserveRequest::Resource).await?;
        resources
            .create(CreateRequest {
                resource: id.clone(),
                backend: "passthrough".into(),
                workspace: Workspace::Directory(".".into()),
                env: BTreeMap::new(),
                ..Default::default()
            })
            .await?;
        ids.push(id);
    }
    let failed = resources
        .spawn(SpawnRequest {
            process: resources
                .reserve(ReserveRequest::Process(ids[0].clone()))
                .await?,
            command: ExecRequest {
                resource: ids[0].clone(),
                argv: vec!["true".into()],
                cwd: None,
                env: BTreeMap::new(),
                stdin: Some(vec![0; 1024 * 1024]),
            },
        })
        .await?;
    // Wait for native completion without consuming the terminal failure.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let slot = resources.slot(&failed.resource).await?;
            let slot = slot.lock().await;
            if slot.as_ref().is_some_and(|entry| {
                entry
                    .processes
                    .get(&failed.process)
                    .is_some_and(|process| !process.is_running())
            }) {
                return Result::Ok(());
            }
            drop(slot);
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(Error::failed)??;
    let mut pids = Vec::new();
    for (index, id) in ids.iter().enumerate() {
        let ready = directory.path().join(index.to_string());
        resources
            .spawn(SpawnRequest {
                process: resources
                    .reserve(ReserveRequest::Process(id.clone()))
                    .await?,
                command: ExecRequest {
                    resource: id.clone(),
                    argv: vec![
                        "sh".into(),
                        "-c".into(),
                        format!(
                            "echo $$ > {}; sleep 600",
                            tinybox_core::shell::quote(&ready.to_string_lossy())
                        ),
                    ],
                    cwd: None,
                    env: BTreeMap::new(),
                    stdin: None,
                },
            })
            .await?;
        let pid = native_ready_pid(&ready).await?;
        pids.push(pid);
    }
    assert!(resources.shutdown().await.is_err());
    let survivors: Vec<_> = pids
        .iter()
        .filter(|pid| std::path::Path::new(&format!("/proc/{}/status", pid.trim())).exists())
        .collect();
    assert!(resources.state.lock().await.entries.is_empty());
    resources.shutdown().await?;
    assert!(
        survivors.is_empty(),
        "shutdown skipped processes after a prior failure: {survivors:?}"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
async fn native_ready_pid(ready: &std::path::Path) -> Result<String> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(pid) = std::fs::read_to_string(ready)
                && !pid.trim().is_empty()
            {
                return pid;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(Error::failed)
}

#[cfg(unix)]
#[tokio::test]
async fn failed_commands_release_native_slots_through_public_cleanup_retries() -> Result<()> {
    let resources = Resources::default();
    for index in 0..=tinybox_bus::MAX_ACTIVE_RESOURCES {
        let id = resources.reserve(ReserveRequest::Resource).await?;
        resources
            .create(CreateRequest {
                resource: id.clone(),
                backend: "passthrough".into(),
                workspace: Workspace::Directory(".".into()),
                env: BTreeMap::new(),
                ..Default::default()
            })
            .await?;
        let cycles = if index == 0 {
            tinybox_bus::MAX_PROCESSES_PER_RESOURCE + 1
        } else {
            1
        };
        for _ in 0..cycles {
            let process = resources
                .spawn(SpawnRequest {
                    process: resources
                        .reserve(ReserveRequest::Process(id.clone()))
                        .await?,
                    command: ExecRequest {
                        resource: id.clone(),
                        argv: vec!["true".into()],
                        cwd: None,
                        env: BTreeMap::new(),
                        stdin: Some(vec![0; 1024 * 1024]),
                    },
                })
                .await?;
            // Drain waits for the deterministic broken pipe before cancellation.
            {
                let slot = resources.slot(&id).await?;
                let slot = slot.lock().await;
                slot.as_ref()
                    .ok_or_else(|| Error::failed("missing fixture"))?
                    .collector
                    .as_ref()
                    .ok_or_else(|| Error::failed("missing collector"))?
                    .drain()
                    .await;
            }
            match index % 3 {
                0 => {
                    assert!(resources.cancel(&process).await.is_err());
                    resources.cancel(&process).await?;
                    assert!(!resources.is_running(&process).await?);
                }
                1 => {
                    assert!(resources.is_running(&process).await.is_err());
                    assert!(!resources.is_running(&process).await?);
                }
                _ => {
                    assert!(resources.close(&id).await.is_err());
                    resources.close(&id).await?;
                }
            }
        }
        resources.close(&id).await?;
        resources.close(&id).await?;
    }
    resources.shutdown().await?;
    assert!(resources.state.lock().await.entries.is_empty());
    Ok(())
}
