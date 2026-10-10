//! Shared provisioning/service Kubernetes client bounds and ambient-authority exclusion.

#![allow(
    clippy::unwrap_used,
    reason = "controlled receiver fixtures fail immediately"
)]

use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    thread,
};

use k8s_openapi::api::apps::v1::Deployment;
use kube::Api;

use super::*;

fn fixture_kubeconfig(server: &str, cluster_fields: &str, user_fields: &str) -> String {
    format!(
        concat!(
            "apiVersion: v1\nkind: Config\nclusters:\n- name: fixture\n  cluster:\n",
            "    server: {server}\n{cluster_fields}\ncontexts:\n- name: fixture\n",
            "  context:\n    cluster: fixture\n    user: fixture\ncurrent-context: fixture\n",
            "users:\n- name: fixture\n  user:\n{user_fields}\n",
        ),
        server = server,
        cluster_fields = cluster_fields,
        user_fields = user_fields,
    )
}

enum ResponseFraming {
    ContentLength,
    Chunked,
    CloseDelimited,
}

async fn request_deployment(body_bytes: usize, framing: ResponseFraming) -> bool {
    let prefix = concat!(
        r#"{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"#,
        r#""name":"bounded","namespace":"demo","uid":"uid-1","resourceVersion":"1"}}"#,
    );
    let mut body = prefix.as_bytes().to_vec();
    body.resize(body_bytes, b' ');

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let receiver_thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).unwrap();

        match framing {
            ResponseFraming::ContentLength => {
                write!(
                    stream,
                    concat!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
                        "content-length: {}\r\nconnection: close\r\n\r\n",
                    ),
                    body.len()
                )
                .unwrap();
                let _ = stream.write_all(&body);
            },
            ResponseFraming::Chunked => {
                stream
                    .write_all(
                        concat!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
                            "transfer-encoding: chunked\r\nconnection: close\r\n\r\n",
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                let _ = write!(stream, "{:x}\r\n", body.len());
                let _ = stream.write_all(&body);
                let _ = stream.write_all(b"\r\n0\r\n\r\n");
            },
            ResponseFraming::CloseDelimited => {
                stream
                    .write_all(
                        concat!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
                            "connection: close\r\n\r\n",
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                let _ = stream.write_all(&body);
            },
        }
    });

    let receiver_url = format!("http://{address}");
    let client_configuration = fixture_kubeconfig(&receiver_url, "", "    token: fixture");
    let client = load_operator_kubernetes_client(client_configuration.as_bytes())
        .await
        .unwrap();
    let request_succeeded = Api::<Deployment>::namespaced(client, "demo")
        .get("bounded")
        .await
        .is_ok();

    receiver_thread.join().unwrap();
    request_succeeded
}

#[tokio::test]
async fn explicit_kubeconfig_rejects_ambient_credential_and_file_sources() {
    for (cluster_fields, user_fields) in [
        (
            "    certificate-authority: /ambient/ca",
            "    token: fixture",
        ),
        ("", "    tokenFile: /ambient/token"),
        ("", "    client-certificate: /ambient/certificate"),
        ("", "    client-key: /ambient/key"),
        (
            "",
            "    exec: {command: /ambient/exec, apiVersion: client.authentication.k8s.io/v1}",
        ),
        ("", "    auth-provider: {name: gcp}"),
    ] {
        let configuration = fixture_kubeconfig("http://127.0.0.1:1", cluster_fields, user_fields);
        let client_result = load_operator_kubernetes_client(configuration.as_bytes()).await;
        assert!(client_result.is_err());
    }

    assert!(load_operator_kubernetes_client(b"").await.is_err());
    let oversized_configuration = vec![b' '; 16 * 1024 + 1];
    assert!(load_operator_kubernetes_client(&oversized_configuration)
        .await
        .is_err());

    let configuration = fixture_kubeconfig("http://127.0.0.1:1", "", "    token: fixture");
    let mut explicit_configuration = kube::config::Kubeconfig::from_yaml(&configuration).unwrap();
    assert!(configure_explicit_kubeconfig(&mut explicit_configuration).unwrap());
    let configured_proxy = explicit_configuration.clusters[0]
        .cluster
        .as_ref()
        .unwrap()
        .proxy_url
        .as_deref();
    assert_eq!(configured_proxy, Some("http://127.0.0.1"));
}

#[tokio::test]
async fn kubernetes_response_limit_accepts_exact_and_rejects_every_oversized_framing() {
    const MAXIMUM: usize = 2 * 1024 * 1024;
    assert!(request_deployment(MAXIMUM, ResponseFraming::ContentLength).await);
    assert!(!request_deployment(MAXIMUM + 1, ResponseFraming::ContentLength).await);
    assert!(!request_deployment(MAXIMUM + 1, ResponseFraming::Chunked).await);
    assert!(!request_deployment(MAXIMUM + 1, ResponseFraming::CloseDelimited).await);
}
