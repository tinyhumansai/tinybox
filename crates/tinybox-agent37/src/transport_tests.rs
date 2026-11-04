//! `HttpTransport` against a one-shot in-process HTTP server, so the real
//! request building (hosts, paths, auth headers) and response handling (2xx,
//! 404, non-2xx, malformed body, connection failure) are covered without the
//! live agent37 service or any extra dependency.

use super::*;

use std::collections::BTreeMap;
use std::error::Error as StdError;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::api::{CreateBody, ExecBody, Network};

type TestResult = std::result::Result<(), Box<dyn StdError>>;

/// A full HTTP/1.1 response with a JSON body and `Connection: close`, so the
/// client reads to EOF.
fn response(status_line: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Bind a loopback listener, answer the first request with `reply`, and return
/// the base URL plus a handle yielding the raw request bytes the client sent.
async fn serve_once(
    reply: String,
) -> std::result::Result<(String, tokio::task::JoinHandle<String>), Box<dyn StdError>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    let handle = tokio::spawn(async move {
        let mut captured = String::new();
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            if let Ok(read) = socket.read(&mut buf).await {
                captured = String::from_utf8_lossy(&buf[..read]).into_owned();
            }
            let _ = socket.write_all(reply.as_bytes()).await;
            let _ = socket.flush().await;
        }
        captured
    });
    Ok((base, handle))
}

fn transport_to(base: &str) -> std::result::Result<HttpTransport, Box<dyn StdError>> {
    Ok(HttpTransport::new(Agent37Config::with_bases(
        base, base, "sk_test",
    ))?)
}

fn create_body() -> CreateBody {
    CreateBody {
        template: "agent37-base".to_owned(),
        resources: None,
        network: Network::DenyAll,
        env: BTreeMap::new(),
        metadata: BTreeMap::new(),
    }
}

#[tokio::test]
async fn create_posts_to_v1_instances_with_a_bearer_header() -> TestResult {
    let (base, server) = serve_once(response(
        "201 Created",
        r#"{"id":"ab12cd34ef","status":"running"}"#,
    ))
    .await?;
    let view = transport_to(&base)?.create(&create_body()).await?;
    assert_eq!(view.id, "ab12cd34ef");
    assert_eq!(view.status, "running");

    let request = server.await?.to_lowercase();
    assert!(
        request.starts_with("post /v1/instances "),
        "request: {request}"
    );
    assert!(
        request.contains("authorization: bearer sk_test"),
        "request: {request}"
    );
    Ok(())
}

#[tokio::test]
async fn exec_posts_to_the_sandbox_host_with_the_key_header() -> TestResult {
    let (base, server) = serve_once(response(
        "200 OK",
        r#"{"exit_code":0,"stdout":"hi\n","stderr":"","truncated":false}"#,
    ))
    .await?;
    let body = ExecBody {
        command: "echo hi".to_owned(),
    };
    let result = transport_to(&base)?.exec("ab12cd34ef", &body).await?;
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout, "hi\n");

    let request = server.await?.to_lowercase();
    assert!(
        request.starts_with("post /v1/instances/ab12cd34ef/exec "),
        "request: {request}"
    );
    assert!(
        request.contains("x-agent37-key: sk_test"),
        "request: {request}"
    );
    // The exec host must not fall back to the bearer header.
    assert!(!request.contains("authorization:"), "request: {request}");
    Ok(())
}

#[tokio::test]
async fn inspect_returns_the_view_on_200() -> TestResult {
    let (base, server) = serve_once(response(
        "200 OK",
        r#"{"id":"ab12cd34ef","status":"sleeping"}"#,
    ))
    .await?;
    let view = transport_to(&base)?.inspect("ab12cd34ef").await?;
    assert_eq!(view.map(|v| v.status), Some("sleeping".to_owned()));
    let request = server.await?.to_lowercase();
    assert!(
        request.starts_with("get /v1/instances/ab12cd34ef "),
        "request: {request}"
    );
    Ok(())
}

#[tokio::test]
async fn inspect_returns_none_on_404() -> TestResult {
    let (base, server) = serve_once(response("404 Not Found", "")).await?;
    assert!(transport_to(&base)?.inspect("gone").await?.is_none());
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn delete_is_ok_on_2xx_and_on_404() -> TestResult {
    let (base, server) = serve_once(response("204 No Content", "")).await?;
    transport_to(&base)?.delete("ab12").await?;
    let _ = server.await;

    let (base, server) = serve_once(response("404 Not Found", "")).await?;
    transport_to(&base)?.delete("already-gone").await?;
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn delete_is_a_backend_error_on_500() -> TestResult {
    let (base, server) = serve_once(response("500 Internal Server Error", "")).await?;
    let error = transport_to(&base)?.delete("ab12").await;
    assert!(matches!(error, Err(Error::Backend { .. })));
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn a_non_success_status_is_a_backend_error() -> TestResult {
    let (base, server) = serve_once(response("500 Internal Server Error", "boom")).await?;
    let error = transport_to(&base)?.create(&create_body()).await;
    assert!(matches!(error, Err(Error::Backend { .. })));
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn a_malformed_body_is_a_backend_error() -> TestResult {
    let (base, server) = serve_once(response("200 OK", "not json")).await?;
    let error = transport_to(&base)?.create(&create_body()).await;
    assert!(matches!(error, Err(Error::Backend { .. })));
    let _ = server.await;
    Ok(())
}

/// An address that refuses connections: bound to claim the port, then dropped.
async fn dead_base() -> std::result::Result<String, Box<dyn StdError>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    Ok(format!("http://{}", listener.local_addr()?))
}

#[tokio::test]
async fn a_create_connection_failure_is_a_backend_error() -> TestResult {
    let base = dead_base().await?;
    assert!(matches!(
        transport_to(&base)?.create(&create_body()).await,
        Err(Error::Backend { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn an_exec_connection_failure_is_a_backend_error() -> TestResult {
    let base = dead_base().await?;
    let body = ExecBody {
        command: "true".to_owned(),
    };
    assert!(matches!(
        transport_to(&base)?.exec("x", &body).await,
        Err(Error::Backend { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn an_inspect_connection_failure_is_a_backend_error() -> TestResult {
    let base = dead_base().await?;
    assert!(matches!(
        transport_to(&base)?.inspect("x").await,
        Err(Error::Backend { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn a_delete_connection_failure_is_a_backend_error() -> TestResult {
    let base = dead_base().await?;
    assert!(matches!(
        transport_to(&base)?.delete("x").await,
        Err(Error::Backend { .. })
    ));
    Ok(())
}

#[test]
fn from_env_runs_the_config_delegation() {
    // The ambient environment decides the outcome, so this only exercises the
    // delegation to `Agent37Config::from_env` — it asserts no particular result.
    let _ = HttpTransport::from_env();
}
