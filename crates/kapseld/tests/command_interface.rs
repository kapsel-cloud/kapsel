//! Installed command discovery and non-disclosing local client failure behavior.
#![allow(clippy::unwrap_used, reason = "controlled command fixtures")]

use std::{ffi::OsString, os::unix::ffi::OsStringExt as _, process::Command};

const CLIENT: &str = env!("CARGO_BIN_EXE_kapsel-service-client");
const DAEMON: &str = env!("CARGO_BIN_EXE_kapseld");

#[test]
fn discovery_needs_no_service_or_configuration() {
    for (binary, name) in [(CLIENT, "kapsel-service-client"), (DAEMON, "kapseld")] {
        let version = Command::new(binary)
            .arg("--version")
            .env_clear()
            .output()
            .unwrap();
        assert!(version.status.success());
        assert_eq!(
            version.stdout,
            format!("{name} {}\n", env!("CARGO_PKG_VERSION")).as_bytes()
        );
        assert!(version.stderr.is_empty());
        let help = Command::new(binary)
            .arg("--help")
            .env_clear()
            .output()
            .unwrap();
        assert!(help.status.success());
        assert!(String::from_utf8(help.stdout).unwrap().contains("Usage:"));
        assert!(help.stderr.is_empty());
    }
}

#[test]
fn invalid_usage_is_bounded_and_does_not_echo_arguments() {
    for binary in [CLIENT, DAEMON] {
        for arguments in [
            vec![],
            vec![OsString::from("SECRET_ARGUMENT")],
            vec![OsString::from("--help"), OsString::from("SECRET_ARGUMENT")],
            vec![
                OsString::from("--version"),
                OsString::from("SECRET_ARGUMENT"),
            ],
            vec![OsString::from_vec(vec![0xff])],
        ] {
            let result = Command::new(binary)
                .args(arguments)
                .env_clear()
                .output()
                .unwrap();
            assert_eq!(result.status.code(), Some(2));
            assert!(result.stdout.is_empty());
            let error = String::from_utf8(result.stderr).unwrap();
            assert!(error.contains("invalid_usage"));
            assert!(!error.contains("SECRET_ARGUMENT"));
            assert!(error.len() < 128);
        }
    }
}

#[cfg(feature = "test-harness")]
mod client_failures {
    use std::{
        fs,
        io::{Read as _, Write as _},
        os::unix::net::UnixListener,
        path::PathBuf,
        process::Output,
        sync::atomic::{AtomicU64, Ordering},
        thread,
    };

    use sha2::{Digest as _, Sha256};

    use super::*;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "kapsel-client-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn run(&self, args: &[&str], response: Option<&[u8]>) -> Output {
            let socket = self.0.join("socket");
            let server = response.map(|response| {
                let listener = UnixListener::bind(&socket).unwrap();
                let response = response.to_vec();
                thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut request = Vec::new();
                    stream.read_to_end(&mut request).unwrap();
                    stream.write_all(&response).unwrap();
                })
            });
            let output = Command::new(CLIENT)
                .args(args)
                .env_clear()
                .env("KAPSELD_TEST_CLIENT_SOCKET", &socket)
                .output()
                .unwrap();
            if let Some(server) = server {
                server.join().unwrap();
                fs::remove_file(socket).unwrap();
            }
            output
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn framed(bytes: &[u8]) -> Vec<u8> {
        let mut result = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
        result.extend_from_slice(bytes);
        result
    }

    fn failure(result: &Output, code: &str) {
        assert_eq!(result.status.code(), Some(4));
        assert!(result.stdout.is_empty());
        let diagnostic = std::str::from_utf8(&result.stderr).unwrap();
        assert!(diagnostic.contains(code), "{diagnostic}");
        assert!(!diagnostic.contains("SECRET"));
        assert!(diagnostic.len() < 160);
    }

    #[test]
    fn connection_exchange_and_protocol_failures_are_distinct() {
        let fixture = Fixture::new();
        failure(
            &fixture.run(&["status", "op"], None),
            "connection_unavailable",
        );
        failure(
            &fixture.run(&["submit", "op"], Some(&[0, 0])),
            "exchange_incomplete",
        );
        failure(
            &fixture.run(
                &["status", "op"],
                Some(&framed(br#"{"version":2,"status":"SECRET_RESPONSE"}"#)),
            ),
            "response_invalid",
        );
        let response = br#"{"version":1,"status":"NOT_ADMITTED","reason":"BUSY"}"#;
        let result = fixture.run(&["submit", "op"], Some(&framed(response)));
        assert!(result.status.success());
        assert_eq!(result.stdout, [response.as_slice(), b"\n"].concat());
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn unavailable_or_invalid_receipt_creates_nothing_and_export_never_replaces() {
        let fixture = Fixture::new();
        let destination = fixture.0.join("SECRET_destination");
        let arguments = ["receipt", "op", destination.to_str().unwrap()];
        failure(
            &fixture.run(
                &arguments,
                Some(&framed(br#"{"version":1,"status":"NOT_READY"}"#)),
            ),
            "receipt_unavailable",
        );
        assert!(!destination.exists());
        let invalid = serde_json::to_vec(&serde_json::json!({
            "version": 1, "status": "READY", "receipt_hex": "00abff",
            "receipt_sha256": "0".repeat(64),
        }))
        .unwrap();
        failure(
            &fixture.run(&arguments, Some(&framed(&invalid))),
            "response_invalid",
        );
        assert!(!destination.exists());
        let relative = fixture.run(&["receipt", "op", "relative-output"], None);
        assert_eq!(relative.status.code(), Some(2));
        let response = serde_json::to_vec(&serde_json::json!({
            "version": 1, "status": "READY", "receipt_hex": "00abff",
            "receipt_sha256": Sha256::digest([0, 0xab, 0xff]).iter()
                .fold(String::new(), |mut text, byte| {
                    use std::fmt::Write as _;
                    write!(text, "{byte:02x}").unwrap();
                    text
                }),
        }))
        .unwrap();
        assert!(fixture
            .run(&arguments, Some(&framed(&response)))
            .status
            .success());
        assert_eq!(fs::read(&destination).unwrap(), [0, 0xab, 0xff]);
        failure(
            &fixture.run(&arguments, Some(&framed(&response))),
            "export_failed",
        );
        assert_eq!(fs::read(&destination).unwrap(), [0, 0xab, 0xff]);
    }
}
