//! Direct child exit, timeout and unwind observations for source-process fixture custody.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "fail-fast owned process fixtures"
)]

use std::{
    io, panic,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[path = "support/child.rs"]
mod child;
use child::ChildGuard;

fn sleeping_child() -> ChildGuard {
    ChildGuard::new(
        Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .spawn()
            .unwrap(),
    )
}

fn assert_retired(pid: u32) {
    let output = ChildGuard::output(Command::new("kill").args(["-0", &pid.to_string()])).unwrap();
    assert!(!output.status.success(), "owned child still exists");
}

#[test]
fn normal_exit_preserves_both_bounded_output_streams() {
    let output = ChildGuard::output(
        Command::new("sh").args(["-c", "printf 'protocol'; printf 'diagnostic' >&2"]),
    )
    .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"protocol");
    assert_eq!(output.stderr, b"diagnostic");
}

#[test]
fn child_timeout_kills_and_reaps_before_returning_failure() {
    let mut child = sleeping_child();
    let pid = child.id();
    let start = Instant::now();
    assert_eq!(
        child
            .wait_for(Duration::from_millis(50))
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(child.try_wait().unwrap().is_some());
    assert_retired(pid);
}

#[test]
fn blocked_stdin_writer_is_inside_the_retirement_deadline() {
    let child = ChildGuard::new(
        Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let pid = child.id();
    let start = Instant::now();
    // Exceed pipe capacity even on hosts that dynamically grow their pipe buffers.
    let error = child
        .write_with_output_for(vec![b'x'; 4 * 1024 * 1024], Duration::from_millis(50))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_retired(pid);
}

#[test]
fn fixture_unwind_kills_and_reaps_its_child() {
    let child = sleeping_child();
    let pid = child.id();
    assert!(panic::catch_unwind(move || {
        let _child = child;
        panic!("injected fixture failure");
    })
    .is_err());
    assert_retired(pid);
}
