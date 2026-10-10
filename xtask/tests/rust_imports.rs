//! Black-box source discovery and failure checks for the Rust import checker.

use std::{
    env, fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT_CHECKOUT: AtomicUsize = AtomicUsize::new(0);

struct Checkout(PathBuf);

impl Checkout {
    fn new() -> Result<Self, String> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos();
        let serial = NEXT_CHECKOUT.fetch_add(1, Ordering::Relaxed);
        let root = env::temp_dir().join(format!(
            "kapsel-import-check-{}-{nonce}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&root).map_err(|error| error.to_string())?;
        let checkout = Self(root);
        checkout.git(&["init", "--quiet"])?;
        Ok(checkout)
    }

    fn git(&self, arguments: &[&str]) -> Result<(), String> {
        let mut command = Command::new("git");
        clear_git_environment(&mut command);
        let output = command
            .args(arguments)
            .current_dir(&self.0)
            .output()
            .map_err(|error| error.to_string())?;
        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).into_owned())
        }
    }

    fn write(&self, name: &str, text: &str) -> Result<(), String> {
        fs::write(self.0.join(name), text).map_err(|error| error.to_string())
    }

    fn check(&self) -> Result<Output, String> {
        Command::new(env!("CARGO_BIN_EXE_check-rust-imports"))
            .current_dir(&self.0)
            .output()
            .map_err(|error| error.to_string())
    }
}

impl Drop for Checkout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn clear_git_environment(command: &mut Command) {
    for (key, _) in env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
}

#[test]
fn discovers_tracked_and_untracked_source_but_not_ignored_files() -> Result<(), String> {
    let checkout = Checkout::new()?;
    checkout.write("tracked.rs", "fn f() {}")?;
    checkout.git(&["add", "tracked.rs"])?;
    checkout.write(".gitignore", "ignored.rs\n")?;
    checkout.write("ignored.rs", "not valid Rust")?;
    checkout.write("new source.rs", "fn f() { use external::Type; }")?;
    let output = checkout.check()?;
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("new source.rs:1:10: block-local-use"),
        "{error}"
    );
    assert!(!error.contains("ignored.rs"));

    checkout.write("new source.rs", "use external::Type; fn f() {}")?;
    let output = checkout.check()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn rejects_nested_invocation_instead_of_checking_a_partial_tree() -> Result<(), String> {
    let checkout = Checkout::new()?;
    fs::create_dir(checkout.0.join("nested")).map_err(|error| error.to_string())?;
    let output = Command::new(env!("CARGO_BIN_EXE_check-rust-imports"))
        .current_dir(checkout.0.join("nested"))
        .output()
        .map_err(|error| error.to_string())?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Git checkout root"));
    Ok(())
}

#[test]
fn invalid_syntax_fails_instead_of_silently_skipping_source() -> Result<(), String> {
    let checkout = Checkout::new()?;
    checkout.write("broken.rs", "fn incomplete(")?;
    let output = checkout.check()?;
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("broken.rs:"), "{error}");
    assert!(error.contains("cannot parse Rust"), "{error}");
    Ok(())
}
