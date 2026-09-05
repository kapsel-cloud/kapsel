//! Named Linux integration scenarios for the staged installer bundle.

#![cfg(unix)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening,
    clippy::unused_self,
    clippy::unwrap_used,
    reason = "fixture failures must stop tests and each test holds its server and serial lock"
)]

use std::{
    fs,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::{fs::MetadataExt as _, process::ExitStatusExt as _},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, OnceLock,
    },
    thread,
    time::{Duration, Instant},
};

use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig, ServerConnection, StreamOwned,
};
use serde_json::Value;

const INSTALLER_STATE: &str = "/var/lib/kapsel-installer";
const TRANSACTION: &str = "/var/lib/kapsel-installer/transaction.json";
const SUCCESSOR: &str = "/var/lib/kapsel-installer/.transaction.next";
const LOCK: &str = "/run/lock/kapsel-installer.lock";
const HOST: &str = "/host-fixture";
const TARGET: &str = "/target";
const OPERATOR: &str = "/secure/kapsel";
const FAILURE_PREFIX: &str = "Kapsel installer failure: ";
const OPERATOR_FILES: &[&str] = &[
    "authorization.pub",
    "bootstrap-kubeconfig.yaml",
    "grant.bin",
    "receipt.seed",
    "receipt.trust",
];
const STATE_FILES: &[&str] = &[
    "group-state",
    "group-next",
    "group-delay",
    "group-command-started",
    "group-timeout",
    "user-timeout",
    "user-command-started",
    "passwd-state",
    "shadow-state",
    "passwd-extra",
    "identity-commands",
    "timeout-commands",
    "kube-requests",
    "kube-mode",
];

static SERIAL: Mutex<()> = Mutex::new(());
static HOST_TOOL: OnceLock<PathBuf> = OnceLock::new();

struct TestEnvironment {
    _serial: MutexGuard<'static, ()>,
    server: FixtureServer,
}

impl TestEnvironment {
    fn new() -> Self {
        let serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_global_state();
        prepare_operator_input();
        prepare_fake_host();
        write_target("kube-mode", b"success\n");
        write_target("kube-requests", b"");
        let server = FixtureServer::start();
        Self {
            _serial: serial,
            server,
        }
    }

    fn reset(&self) {
        reset_installer_state();
        for name in STATE_FILES {
            let _ = fs::remove_file(target(name));
        }
        write_target("identity-commands", b"");
        write_target("timeout-commands", b"");
        write_target("kube-requests", b"");
        write_target("kube-mode", b"success\n");
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        self.server.stop();
        reset_global_state();
    }
}

struct FixtureServer {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl FixtureServer {
    fn start() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certificate = CertificateDer::from(
            fs::read(target("kube.der")).expect("fixture certificate DER must be readable"),
        );
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            fs::read(target("kube-key.der")).expect("fixture key DER must be readable"),
        ));
        let config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate], key)
                .expect("fixture certificate and key must match"),
        );
        let listener = TcpListener::bind(("127.0.0.1", 6443))
            .expect("fixture Kubernetes TLS listener must bind");
        listener
            .set_nonblocking(true)
            .expect("fixture listener must become nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => serve_kubernetes_request(stream, Arc::clone(&config)),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    },
                    Err(error) => panic!("fixture listener failed: {error}"),
                }
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("fixture server thread must stop");
        }
    }
}

fn serve_kubernetes_request(stream: TcpStream, config: Arc<ServerConfig>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("fixture stream read timeout must be set");
    let connection = ServerConnection::new(config).expect("fixture TLS connection must initialize");
    let mut stream = StreamOwned::new(connection, stream);
    let mut request = Vec::new();
    let mut buffer = [0_u8; 2048];
    while request.len() <= 16 * 1024 && !request.windows(4).any(|part| part == b"\r\n\r\n") {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(length) => request.extend_from_slice(&buffer[..length]),
        }
    }
    let Some(line) = request.split(|byte| *byte == b'\n').next() else {
        return;
    };
    let Ok(line) = std::str::from_utf8(line) else {
        return;
    };
    let mut fields = line.trim_end_matches('\r').split_whitespace();
    let (Some(method), Some(path)) = (fields.next(), fields.next()) else {
        return;
    };
    append_target("kube-requests", &format!("{method} {path}\n"));
    let mode = read_target("kube-mode").trim().to_owned();
    let (status, body) = kubernetes_response(&mode, method, path);
    let response = format!(
        concat!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\n",
            "Content-Length: {}\r\nConnection: close\r\n\r\n{}"
        ),
        status,
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn kubernetes_response(mode: &str, method: &str, path: &str) -> (&'static str, String) {
    if method != "GET" {
        return (
            "405 Method Not Allowed",
            concat!(
                r#"{"kind":"Status","apiVersion":"v1","status":"Failure","#,
                r#""reason":"MethodNotAllowed","code":405}"#
            )
            .to_owned(),
        );
    }
    if mode == "api-failure" && path == "/api/v1/namespaces/demo" {
        return (
            "500 Internal Server Error",
            concat!(
                r#"{"kind":"Status","apiVersion":"v1","status":"Failure","#,
                r#""reason":"InternalError","code":500}"#
            )
            .to_owned(),
        );
    }
    if path == "/api/v1/namespaces/demo" {
        return (
            "200 OK",
            concat!(
                r#"{"apiVersion":"v1","kind":"Namespace","metadata":{"#,
                r#""name":"demo","uid":"namespace-uid"}}"#
            )
            .to_owned(),
        );
    }
    if path == "/apis/apps/v1/namespaces/demo/deployments/agent-api" {
        return (
            "200 OK",
            concat!(
                r#"{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"#,
                r#""name":"agent-api","namespace":"demo","uid":"deployment-uid"},"#,
                r#""spec":{"selector":{"matchLabels":{"app":"agent-api"}},"#,
                r#""template":{"metadata":{"labels":{"app":"agent-api"}},"#,
                r#""spec":{"containers":[{"name":"api","#,
                r#""image":"example.invalid/image@sha256:"#,
                "1111111111111111111111111111111111111111111111111111111111111111",
                r#""}]}}}}"#
            )
            .to_owned(),
        );
    }
    if mode == "role-conflict"
        && path
            == "/apis/rbac.authorization.k8s.io/v1/namespaces/demo/roles/kapsel-service-agent-api"
    {
        return (
            "200 OK",
            concat!(
                r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","#,
                r#""metadata":{"name":"kapsel-service-agent-api","namespace":"demo","#,
                r#""uid":"hostile-role"}}"#
            )
            .to_owned(),
        );
    }
    (
        "404 Not Found",
        concat!(
            r#"{"kind":"Status","apiVersion":"v1","status":"Failure","#,
            r#""reason":"NotFound","code":404}"#
        )
        .to_owned(),
    )
}

fn reset_global_state() {
    reset_installer_state();
    let _ = fs::remove_dir_all("/secure");
    let _ = fs::remove_dir_all(HOST);
    for name in STATE_FILES {
        let _ = fs::remove_file(target(name));
    }
}

fn reset_installer_state() {
    let _ = fs::remove_dir_all(INSTALLER_STATE);
    let _ = fs::remove_file(LOCK);
}

fn prepare_operator_input() {
    fs::create_dir_all(OPERATOR).expect("operator directory must be created");
    set_mode(OPERATOR, 0o700);
    for name in OPERATOR_FILES {
        let source = Path::new("/operator-fixture").join(name);
        let destination = Path::new(OPERATOR).join(name);
        fs::copy(source, &destination).expect("operator fixture file must copy");
        set_mode(&destination, 0o600);
    }
}

fn prepare_fake_host() {
    for directory in [
        "usr/sbin",
        "usr/bin",
        "run/systemd/system",
        "etc/systemd/system/multi-user.target.wants",
        "var/lib",
        "usr/lib/systemd/system",
        "usr/lib/sysusers.d",
        "usr/libexec",
        "usr/share/doc",
    ] {
        fs::create_dir_all(Path::new(HOST).join(directory))
            .unwrap_or_else(|error| panic!("host fixture directory {directory} failed: {error}"));
    }
    let helper = compile_host_tool();
    for tool in [
        "usr/sbin/groupadd",
        "usr/sbin/groupdel",
        "usr/sbin/useradd",
        "usr/sbin/nologin",
        "usr/bin/getent",
        "usr/bin/systemctl",
        "usr/bin/timeout",
    ] {
        let destination = Path::new(HOST).join(tool);
        fs::copy(helper, &destination)
            .unwrap_or_else(|error| panic!("fake host tool {tool} failed: {error}"));
        set_mode(destination, 0o755);
    }
}

fn compile_host_tool() -> &'static PathBuf {
    HOST_TOOL.get_or_init(|| {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/host_tool.rs");
        let output = target("kapsel-installer-host-tool");
        let status = Command::new("rustc")
            .args(["--edition=2021", "-o"])
            .arg(&output)
            .arg(source)
            .status()
            .expect("rustc must start for the host-tool fixture");
        assert!(status.success(), "host-tool fixture must compile");
        output
    })
}

fn set_mode(path: impl AsRef<Path>, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("fixture mode must be set");
}

fn target(name: &str) -> PathBuf {
    Path::new(TARGET).join(name)
}

fn write_target(name: &str, bytes: &[u8]) {
    fs::write(target(name), bytes).unwrap_or_else(|error| panic!("write {name} failed: {error}"));
}

fn append_target(name: &str, value: &str) {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(target(name))
        .unwrap_or_else(|error| panic!("append {name} failed: {error}"));
    file.write_all(value.as_bytes())
        .unwrap_or_else(|error| panic!("append bytes to {name} failed: {error}"));
}

fn read_target(name: &str) -> String {
    fs::read_to_string(target(name)).unwrap_or_default()
}

fn installer_command(action: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kapsel-installer"));
    command
        .args([
            action,
            "--operator-input",
            OPERATOR,
            "--kube-context",
            "nonprod",
        ])
        .env_clear()
        .env("KAPSEL_INSTALLER_TEST_HOST_ROOT", HOST);
    command
}

fn run_failure(action: &str, class: &str) -> Output {
    run_failure_with(action, class, None)
}

fn run_failure_with(action: &str, class: &str, fail_seam: Option<&str>) -> Output {
    let mut command = installer_command(action);
    if let Some(seam) = fail_seam {
        command.env("KAPSEL_INSTALLER_TEST_FAIL_AT_SEAM", seam);
    }
    let output = command.output().expect("installer process must start");
    assert_eq!(
        output.status.code(),
        Some(1),
        "installer output: {output:?}"
    );
    assert!(output.stdout.is_empty(), "installer stdout must stay empty");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!("{FAILURE_PREFIX}{class}\n")
    );
    output
}

fn wait_for_unlocked_install(bound: Duration) {
    let deadline = Instant::now() + bound;
    loop {
        let output = installer_command("install")
            .output()
            .expect("recovery installer process must start");
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr == format!("{FAILURE_PREFIX}implementation_incomplete\n") {
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            return;
        }
        assert_eq!(
            stderr,
            format!("{FAILURE_PREFIX}installer_lock_failure\n"),
            "unexpected recovery output: {output:?}"
        );
        assert!(Instant::now() < deadline, "installer lock was not released");
        thread::sleep(Duration::from_millis(10));
    }
}

fn run_killed(stop_seam: &str, fail_seam: Option<&str>) {
    let mut command = installer_command("install");
    command
        .env("KAPSEL_INSTALLER_TEST_STOP_AT_SEAM", stop_seam)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(seam) = fail_seam {
        command.env("KAPSEL_INSTALLER_TEST_FAIL_AT_SEAM", seam);
    }
    let mut child = command.spawn().expect("installer process must start");
    wait_for_stopped(&child, stop_seam);
    child.kill().expect("stopped installer must accept SIGKILL");
    let status = child.wait().expect("killed installer must be reaped");
    let shell_status = status.signal().map(|signal| 128 + signal);
    assert_eq!(
        shell_status,
        Some(137),
        "{stop_seam} must exit as SIGKILL/137"
    );
}

fn wait_for_stopped(child: &Child, seam: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let status = fs::read_to_string(format!("/proc/{}/status", child.id())).unwrap_or_default();
        if status.lines().any(|line| line.starts_with("State:\tT")) {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("installer did not stop at seam {seam}");
}

fn transaction() -> Value {
    serde_json::from_slice(&fs::read(TRANSACTION).expect("transaction must be readable"))
        .expect("transaction must be valid JSON")
}

fn assert_phase(phase: &str) {
    assert_eq!(transaction()["phase"], phase);
}

fn assert_get_only() {
    let requests = read_target("kube-requests");
    assert!(!requests.is_empty(), "expected Kubernetes observations");
    assert!(
        requests.lines().all(|line| line.starts_with("GET /")),
        "unexpected Kubernetes request:\n{requests}"
    );
}

fn assert_no_installed_files() {
    for path in [
        "etc/kapsel",
        "var/lib/kapsel",
        "run/kapsel",
        "usr/libexec/kapsel",
        "usr/share/kapsel",
        "usr/share/doc/kapsel",
        "usr/bin/kapsel",
        "usr/bin/kapsel-service-client",
        "usr/lib/systemd/system/kapseld.service",
        "usr/lib/sysusers.d/kapseld.conf",
    ] {
        assert!(
            !Path::new(HOST).join(path).exists(),
            "unexpected host path {path}"
        );
    }
}

fn assert_identities_owned() {
    let record = transaction();
    let id = record["transaction_id"]
        .as_str()
        .expect("transaction id must be a string");
    assert_eq!(
        read_target("group-state"),
        "kapsel:x:997:\nkapsel-service-callers:x:996:\n"
    );
    assert_eq!(
        read_target("passwd-state"),
        format!(
            "kapsel:x:999:997:{id}:/var/lib/kapsel:/usr/sbin/nologin\n\
             kapsel-service-caller:x:998:996:{id}:/nonexistent:/usr/sbin/nologin\n"
        )
    );
    assert_eq!(
        read_target("shadow-state"),
        "kapsel:!:20000::::::\nkapsel-service-caller:!:20000::::::\n"
    );
    assert!(record["pending"].is_null());
    let resources = record["host_resources"]
        .as_array()
        .expect("host resources must be an array");
    assert_eq!(resources.len(), 4);
    assert_eq!(resources[0]["name"], "kapsel");
    assert_eq!(resources[0]["gid"], 997);
    assert_eq!(resources[1]["name"], "kapsel-service-callers");
    assert_eq!(resources[1]["gid"], 996);
    assert_eq!(resources[2]["name"], "kapsel");
    assert_eq!(resources[2]["locked"], true);
    assert_eq!(resources[3]["name"], "kapsel-service-caller");
    assert_eq!(resources[3]["locked"], true);
}

fn line_count(name: &str) -> usize {
    read_target(name).lines().count()
}

#[test]
#[ignore = "requires the staged root Linux Docker fixture"]
fn absent_actions_and_idempotent_install_preserve_durable_identity_evidence() {
    let environment = TestEnvironment::new();
    run_failure("refresh-credential", "transaction_failure");
    assert!(!Path::new(INSTALLER_STATE).exists());
    run_failure("uninstall", "transaction_failure");
    assert!(!Path::new(INSTALLER_STATE).exists());
    assert_eq!(line_count("kube-requests"), 0);

    environment.reset();
    run_failure("install", "implementation_incomplete");
    assert_phase("installing");
    assert_identities_owned();
    assert_get_only();
    assert_eq!(line_count("kube-requests"), 5);
    assert_eq!(line_count("identity-commands"), 4);
    let commands = read_target("identity-commands");
    assert!(commands.contains("groupadd --system --gid 997 kapsel\n"));
    assert!(commands.contains("groupadd --system --gid 996 kapsel-service-callers\n"));
    assert!(commands.contains("useradd --system --uid 999 --gid 997"));
    assert!(commands.contains("useradd --system --uid 998 --gid 996"));

    let before = fs::read(TRANSACTION).expect("transaction must be readable");
    let request_count = line_count("kube-requests");
    run_failure("install", "implementation_incomplete");
    assert_eq!(fs::read(TRANSACTION).unwrap(), before);
    assert_eq!(line_count("kube-requests"), request_count);
    assert_eq!(line_count("identity-commands"), 4);
    run_failure("refresh-credential", "implementation_incomplete");
    run_failure("uninstall", "implementation_incomplete");
    assert_eq!(line_count("kube-requests"), request_count);
    assert_identities_owned();
    assert_no_installed_files();

    let initial = transaction()["bootstrap_kubeconfig_initial_sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    let kubeconfig = Path::new(OPERATOR).join("bootstrap-kubeconfig.yaml");
    let renewed = fs::read_to_string(&kubeconfig)
        .unwrap()
        .replace("token: fixture-token", "token: renewed-token");
    fs::write(kubeconfig, renewed).unwrap();
    run_failure("install", "implementation_incomplete");
    let record = transaction();
    assert_eq!(record["bootstrap_kubeconfig_initial_sha256"], initial);
    assert_ne!(record["bootstrap_kubeconfig_sha256"], initial);
    assert_eq!(line_count("kube-requests"), request_count);
}

#[test]
#[ignore = "requires the staged root Linux Docker fixture"]
fn host_and_kubernetes_preflight_refusals_preserve_the_prepared_boundary() {
    let environment = TestEnvironment::new();
    let occupied = Path::new(HOST).join("usr/bin/kapsel");
    fs::write(&occupied, b"sentinel").unwrap();
    set_mode(&occupied, 0o711);
    let before = fs::metadata(&occupied).unwrap();
    let before_bytes = fs::read(&occupied).unwrap();
    run_failure("install", "host_preflight_failure");
    assert_phase("prepared");
    let after = fs::metadata(&occupied).unwrap();
    assert_eq!(before.ino(), after.ino());
    assert_eq!(before.mode(), after.mode());
    assert_eq!(before.len(), after.len());
    assert_eq!(fs::read(&occupied).unwrap(), before_bytes);
    fs::remove_file(&occupied).unwrap();
    assert_eq!(line_count("kube-requests"), 0);

    environment.reset();
    write_target("kube-mode", b"role-conflict\n");
    run_failure("install", "kubernetes_preflight_failure");
    assert_phase("prepared");
    assert_get_only();
    assert_no_installed_files();
    assert!(!target("group-state").exists());

    environment.reset();
    write_target("kube-mode", b"api-failure\n");
    run_failure("install", "kubernetes_preflight_failure");
    assert_phase("prepared");
    assert_get_only();
    assert_no_installed_files();
    assert!(!target("group-state").exists());
}

#[test]
#[ignore = "requires the staged root Linux Docker fixture"]
fn transaction_publication_crashes_recover_without_repeating_completed_preflight() {
    let environment = TestEnvironment::new();
    run_killed("successor-inode-synced", None);
    assert_phase("prepared");
    assert!(!Path::new(SUCCESSOR).exists());
    let first = line_count("kube-requests");
    run_failure("install", "implementation_incomplete");
    assert_phase("installing");
    assert_identities_owned();
    assert!(line_count("kube-requests") > first);

    environment.reset();
    run_killed("successor-linked", None);
    assert_phase("prepared");
    assert!(Path::new(SUCCESSOR).exists());
    let first = line_count("kube-requests");
    run_failure("install", "implementation_incomplete");
    assert_phase("installing");
    assert_identities_owned();
    assert!(!Path::new(SUCCESSOR).exists());
    assert_eq!(line_count("kube-requests"), first);

    environment.reset();
    run_killed("successor-renamed", None);
    assert_phase("installing");
    assert!(!Path::new(SUCCESSOR).exists());
    let first = line_count("kube-requests");
    run_failure("install", "implementation_incomplete");
    assert_identities_owned();
    assert_eq!(line_count("kube-requests"), first);
}

#[test]
#[ignore = "requires the staged root Linux Docker fixture"]
fn hostile_transaction_successor_is_preserved_and_refused_for_install_and_refresh() {
    let _environment = TestEnvironment::new();
    run_killed("successor-inode-synced", None);
    let current = fs::read_to_string(TRANSACTION).unwrap();
    let hostile = current.replace("\"phase\":\"prepared\"", "\"phase\":\"installed\"");
    fs::write(SUCCESSOR, hostile).unwrap();
    set_mode(SUCCESSOR, 0o600);
    let id = transaction()["transaction_id"].as_str().unwrap().to_owned();
    rustix::fs::setxattr(
        SUCCESSOR,
        "user.kapsel.transaction-id",
        id.as_bytes(),
        rustix::fs::XattrFlags::CREATE,
    )
    .expect("hostile successor marker must be set");
    let before = fs::read(SUCCESSOR).unwrap();
    run_failure("install", "transaction_failure");
    assert_eq!(fs::read(SUCCESSOR).unwrap(), before);
    run_failure("refresh-credential", "transaction_failure");
    assert_eq!(fs::read(SUCCESSOR).unwrap(), before);
    assert_phase("prepared");
    assert_get_only();
    assert_no_installed_files();
    assert!(!target("group-state").exists());
}

#[test]
#[ignore = "requires the staged root Linux Docker fixture"]
fn group_creation_crashes_conflicts_and_timeout_recover_without_duplicate_effects() {
    let environment = TestEnvironment::new();
    run_killed("group-pending", None);
    assert_phase("installing");
    assert_eq!(transaction()["pending"]["action"], "create_group");
    assert!(!target("group-state").exists());
    run_failure("install", "implementation_incomplete");
    assert_identities_owned();
    assert_eq!(line_count("identity-commands"), 4);

    environment.reset();
    run_killed("group-command-complete", None);
    assert!(target("group-state").exists());
    assert_eq!(transaction()["pending"]["action"], "create_group");
    run_failure("install", "implementation_incomplete");
    assert_identities_owned();
    assert_eq!(line_count("identity-commands"), 4);

    environment.reset();
    run_killed("group-pending", None);
    write_target("group-state", b"kapsel:x:996:\n");
    let before = fs::read(TRANSACTION).unwrap();
    run_failure("install", "host_mutation_failure");
    assert_eq!(fs::read(TRANSACTION).unwrap(), before);
    assert_eq!(read_target("group-state"), "kapsel:x:996:\n");
    assert_eq!(line_count("identity-commands"), 0);

    environment.reset();
    run_failure("install", "implementation_incomplete");
    write_target("group-state", b"kapsel:x:996:\n");
    let before = fs::read(TRANSACTION).unwrap();
    run_failure("install", "host_mutation_failure");
    assert_eq!(fs::read(TRANSACTION).unwrap(), before);
    assert_eq!(line_count("identity-commands"), 4);

    environment.reset();
    run_killed("second-group-pending", None);
    assert_eq!(read_target("group-state"), "kapsel:x:997:\n");
    assert_eq!(transaction()["pending"]["name"], "kapsel-service-callers");
    run_failure("install", "implementation_incomplete");
    assert_identities_owned();
    assert_eq!(line_count("identity-commands"), 4);

    environment.reset();
    run_killed("second-group-command-complete", None);
    assert_eq!(
        read_target("group-state"),
        "kapsel:x:997:\nkapsel-service-callers:x:996:\n"
    );
    run_failure("install", "implementation_incomplete");
    assert_identities_owned();
    assert_eq!(line_count("identity-commands"), 4);

    environment.reset();
    run_killed("second-group-pending", None);
    append_target("group-state", "kapsel-service-callers:x:995:\n");
    let before = fs::read(TRANSACTION).unwrap();
    run_failure("install", "host_mutation_failure");
    assert_eq!(fs::read(TRANSACTION).unwrap(), before);
    assert_eq!(line_count("identity-commands"), 1);

    environment.reset();
    write_target("group-timeout", b"");
    run_failure("install", "host_mutation_failure");
    assert!(!target("group-state").exists());
    assert_eq!(transaction()["pending"]["action"], "create_group");
    assert_eq!(line_count("identity-commands"), 1);
    assert_eq!(read_target("group-state"), "");
}

#[test]
#[ignore = "requires the staged root Linux Docker fixture"]
fn user_creation_crashes_ambiguity_conflict_and_timeout_become_durable_evidence() {
    let environment = TestEnvironment::new();
    run_killed("service-user-pending", None);
    assert_eq!(
        read_target("group-state"),
        "kapsel:x:997:\nkapsel-service-callers:x:996:\n"
    );
    assert!(!target("passwd-state").exists());
    assert_eq!(transaction()["pending"]["action"], "create_user");
    run_failure("install", "implementation_incomplete");
    assert_identities_owned();

    environment.reset();
    run_killed("service-user-command-complete", None);
    assert_eq!(line_count("passwd-state"), 1);
    run_failure("install", "implementation_incomplete");
    assert_identities_owned();
    assert_eq!(line_count("identity-commands"), 4);

    environment.reset();
    run_killed("caller-user-pending", None);
    assert_eq!(line_count("passwd-state"), 1);
    assert_eq!(transaction()["pending"]["name"], "kapsel-service-caller");
    run_failure("install", "implementation_incomplete");
    assert_identities_owned();

    environment.reset();
    run_killed("caller-user-command-complete", None);
    assert_eq!(line_count("passwd-state"), 2);
    run_failure("install", "implementation_incomplete");
    assert_identities_owned();
    assert_eq!(line_count("identity-commands"), 4);

    environment.reset();
    write_target("user-timeout", b"");
    run_failure("install", "host_mutation_failure");
    assert_eq!(
        read_target("group-state"),
        "kapsel:x:997:\nkapsel-service-callers:x:996:\n"
    );
    assert!(!target("passwd-state").exists());
    assert_eq!(transaction()["pending"]["action"], "create_user");
    assert_eq!(line_count("identity-commands"), 3);
    fs::remove_file(target("user-timeout")).unwrap();
    run_failure("install", "implementation_incomplete");
    assert_identities_owned();
    assert_eq!(line_count("identity-commands"), 5);

    environment.reset();
    run_killed("service-user-pending", None);
    let id = transaction()["transaction_id"].as_str().unwrap().to_owned();
    write_target(
        "passwd-state",
        format!("kapsel:x:999:997:{id}:/var/lib/kapsel:/usr/sbin/nologin\n").as_bytes(),
    );
    run_failure("install", "host_mutation_failure");
    assert_phase("identity_blocked");
    let blocked = fs::read(TRANSACTION).unwrap();
    assert!(!target("shadow-state").exists());
    assert_eq!(line_count("identity-commands"), 2);
    fs::remove_file(target("passwd-state")).unwrap();
    run_failure("install", "host_mutation_failure");
    assert_eq!(fs::read(TRANSACTION).unwrap(), blocked);
    assert_eq!(line_count("identity-commands"), 2);

    environment.reset();
    run_killed("service-user-pending", None);
    let id = transaction()["transaction_id"].as_str().unwrap().to_owned();
    write_target(
        "passwd-state",
        format!("kapsel:x:999:997:{id}:/wrong:/usr/sbin/nologin\n").as_bytes(),
    );
    write_target("shadow-state", b"kapsel:!:20000::::::\n");
    run_failure("install", "host_mutation_failure");
    assert_phase("identity_blocked");
    let blocked = fs::read(TRANSACTION).unwrap();
    assert_eq!(line_count("identity-commands"), 2);
    fs::remove_file(target("passwd-state")).unwrap();
    fs::remove_file(target("shadow-state")).unwrap();
    run_failure("install", "host_mutation_failure");
    assert_eq!(fs::read(TRANSACTION).unwrap(), blocked);
    assert_eq!(line_count("identity-commands"), 2);
}

#[test]
#[ignore = "requires the staged root Linux Docker fixture"]
fn reverse_group_rollback_crashes_and_late_primary_users_never_delete_unowned_state() {
    let environment = TestEnvironment::new();
    run_failure_with(
        "install",
        "implementation_incomplete",
        Some("first-group-complete"),
    );
    assert_phase("rolled_back");
    assert!(!target("group-state").exists());
    assert_eq!(
        read_target("identity-commands"),
        "groupadd --system --gid 997 kapsel\ngroupdel kapsel\n"
    );
    assert_eq!(
        read_target("timeout-commands"),
        format!(
            "timeout --signal=KILL 10s {HOST}/usr/sbin/groupadd --system --gid 997 kapsel\n\
             timeout --signal=KILL 10s {HOST}/usr/sbin/groupdel kapsel\n"
        )
    );
    assert_eq!(
        fake_getent(&["group", "unrelated"]),
        "unrelated:x:998:member\n"
    );
    assert_no_installed_files();

    environment.reset();
    run_killed(
        "group-rollback-before-pending",
        Some("first-group-complete"),
    );
    write_target("group-state", b"kapsel:x:996:\n");
    let before = fs::read(TRANSACTION).unwrap();
    run_failure("install", "host_mutation_failure");
    assert_eq!(fs::read(TRANSACTION).unwrap(), before);
    assert_eq!(read_target("group-state"), "kapsel:x:996:\n");
    assert_eq!(line_count("identity-commands"), 1);

    environment.reset();
    run_killed(
        "group-remove-command-complete",
        Some("first-group-complete"),
    );
    assert!(!target("group-state").exists());
    assert_eq!(transaction()["pending"]["action"], "remove_group");
    run_failure("install", "implementation_incomplete");
    assert_phase("rolled_back");
    assert_eq!(line_count("identity-commands"), 2);

    environment.reset();
    run_killed("group-remove-pending", Some("first-group-complete"));
    write_target("passwd-extra", b"late:x:2000:997::/:/usr/sbin/nologin\n");
    let before = fs::read(TRANSACTION).unwrap();
    run_failure("install", "host_mutation_failure");
    assert_eq!(fs::read(TRANSACTION).unwrap(), before);
    assert_eq!(read_target("group-state"), "kapsel:x:997:\n");
    assert_eq!(line_count("identity-commands"), 1);

    environment.reset();
    run_failure_with(
        "install",
        "implementation_incomplete",
        Some("second-group-complete"),
    );
    assert_phase("rolled_back");
    assert!(!target("group-state").exists());
    assert_eq!(
        read_target("identity-commands"),
        concat!(
            "groupadd --system --gid 997 kapsel\n",
            "groupadd --system --gid 996 kapsel-service-callers\n",
            "groupdel kapsel-service-callers\n",
            "groupdel kapsel\n"
        )
    );

    environment.reset();
    run_killed("second-group-remove-pending", Some("second-group-complete"));
    write_target("passwd-extra", b"late:x:2000:996::/:/usr/sbin/nologin\n");
    let before = fs::read(TRANSACTION).unwrap();
    run_failure("install", "host_mutation_failure");
    assert_eq!(fs::read(TRANSACTION).unwrap(), before);
    assert_eq!(
        read_target("group-state"),
        "kapsel:x:997:\nkapsel-service-callers:x:996:\n"
    );
    assert_eq!(line_count("identity-commands"), 2);

    environment.reset();
    run_killed(
        "second-group-remove-command-complete",
        Some("second-group-complete"),
    );
    assert_eq!(read_target("group-state"), "kapsel:x:997:\n");
    run_failure("install", "implementation_incomplete");
    assert_phase("rolled_back");
    assert!(!target("group-state").exists());
    assert_eq!(line_count("identity-commands"), 4);
}

#[test]
#[ignore = "requires the staged root Linux Docker fixture"]
fn inherited_lock_survives_parent_sigkill_until_the_identity_child_finishes() {
    let _environment = TestEnvironment::new();
    write_target("group-delay", b"");
    let mut first = installer_command("install");
    first.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = first.spawn().expect("delayed installer must start");
    wait_for_file("group-command-started", Duration::from_secs(15));
    child.kill().expect("delayed installer must accept SIGKILL");
    let status = child.wait().expect("killed installer must be reaped");
    assert_eq!(status.signal().map(|signal| 128 + signal), Some(137));
    run_failure("install", "installer_lock_failure");
    wait_for_file("group-state", Duration::from_secs(15));
    fs::remove_file(target("group-delay")).unwrap();
    wait_for_unlocked_install(Duration::from_secs(15));
    assert_identities_owned();
    assert_eq!(line_count("identity-commands"), 4);
}

fn wait_for_file(name: &str, bound: Duration) {
    let deadline = Instant::now() + bound;
    while Instant::now() < deadline {
        if target(name).exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("fixture file {name} did not appear");
}

fn fake_getent(arguments: &[&str]) -> String {
    let output = Command::new(Path::new(HOST).join("usr/bin/getent"))
        .args(arguments)
        .output()
        .expect("fake getent must run");
    assert!(output.status.success());
    String::from_utf8(output.stdout).expect("fake getent output must be UTF-8")
}

#[test]
#[ignore = "requires the staged root Linux Docker fixture"]
fn native_debian_tools_compose_through_one_complete_installer_identity_path() {
    let _environment = TestEnvironment::new();
    for tool in [
        "/usr/sbin/groupadd",
        "/usr/sbin/groupdel",
        "/usr/sbin/useradd",
        "/usr/sbin/nologin",
        "/usr/bin/getent",
        "/usr/bin/timeout",
    ] {
        let destination = Path::new(HOST).join(tool.trim_start_matches('/'));
        fs::copy(tool, &destination)
            .unwrap_or_else(|error| panic!("native tool {tool} failed to copy: {error}"));
        set_mode(destination, 0o755);
    }
    let cleanup = NativeIdentityCleanup;
    run_failure("install", "implementation_incomplete");
    let record = transaction();
    let resources = record["host_resources"].as_array().unwrap();
    assert_eq!(resources.len(), 4);
    let primary_group_id = resources[0]["gid"].as_u64().unwrap().to_string();
    let caller_group_id = resources[1]["gid"].as_u64().unwrap().to_string();
    let daemon_user_id = resources[2]["uid"].as_u64().unwrap().to_string();
    let caller_user_id = resources[3]["uid"].as_u64().unwrap().to_string();
    let service_group = native_getent(&["group", "kapsel"]);
    assert_eq!(native_getent(&["group", &primary_group_id]), service_group);
    let callers_group = native_getent(&["group", "kapsel-service-callers"]);
    assert_eq!(native_getent(&["group", &caller_group_id]), callers_group);
    assert_eq!(
        native_getent(&["passwd", &daemon_user_id]),
        native_getent(&["passwd", "kapsel"])
    );
    assert_eq!(
        native_getent(&["passwd", &caller_user_id]),
        native_getent(&["passwd", "kapsel-service-caller"])
    );
    assert!(native_getent(&["shadow", "kapsel"]).starts_with("kapsel:!:"));
    assert!(
        native_getent(&["shadow", "kapsel-service-caller"]).starts_with("kapsel-service-caller:!:")
    );
    assert_get_only();
    assert_no_installed_files();
    drop(cleanup);
}

fn native_getent(arguments: &[&str]) -> String {
    let output = Command::new("/usr/bin/getent")
        .args(arguments)
        .output()
        .expect("native getent must run");
    assert!(output.status.success(), "native getent failed: {output:?}");
    String::from_utf8(output.stdout).expect("native getent output must be UTF-8")
}

struct NativeIdentityCleanup;

impl Drop for NativeIdentityCleanup {
    fn drop(&mut self) {
        for user in ["kapsel-service-caller", "kapsel"] {
            let _ = Command::new("/usr/sbin/userdel")
                .arg(user)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        for group in ["kapsel-service-callers", "kapsel"] {
            let _ = Command::new("/usr/sbin/groupdel")
                .arg(group)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}
