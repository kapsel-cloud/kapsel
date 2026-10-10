//! Regression tests for locating the checkout root at xtask invocation time.

use std::{
    env,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

struct TempTree {
    path: PathBuf,
}

impl TempTree {
    fn new(name: &str) -> Result<Self, String> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("clock before Unix epoch: {error}"))?
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "kapsel-xtask-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn compiled_binary_uses_invocation_checkout_root() -> Result<(), String> {
    let checkout_a = git_checkout("a", "checkout-A")?;
    let checkout_b = git_checkout("b", "checkout-B")?;
    let binary = xtask_binary();

    let output_a = run_xtask(&binary, checkout_a.path(), ["fmt"])?;
    assert!(output_a.status.success());
    assert_eq!(output_a.stdout, b"checkout-A\n");
    assert_eq!(output_a.stderr, b"");

    let nested_b = checkout_b.path().join("nested").join("cwd");
    fs::create_dir_all(&nested_b)
        .map_err(|error| format!("failed to create {}: {error}", nested_b.display()))?;
    let output_b = run_xtask(&binary, &nested_b, ["fmt"])?;
    assert!(output_b.status.success());
    assert_eq!(output_b.stdout, b"checkout-B\n");
    assert_eq!(output_b.stderr, b"");

    let redirected_output = Command::new(&binary)
        .arg("fmt")
        .current_dir(&nested_b)
        .env("GIT_DIR", checkout_a.path().join(".git"))
        .env("GIT_WORK_TREE", checkout_a.path())
        .output()
        .map_err(|error| format!("failed to run {}: {error}", binary.display()))?;
    assert!(redirected_output.status.success());
    assert_eq!(redirected_output.stdout, b"checkout-B\n");
    assert_eq!(redirected_output.stderr, b"");

    Ok(())
}

#[test]
fn refuses_invalid_invocations_and_incomplete_checkouts() -> Result<(), String> {
    let outside = TempTree::new("outside")?;
    let checkout = git_checkout("reject", "reject-marker")?;
    let missing_manifest = git_checkout("missing-manifest", "missing-manifest-marker")?;
    let missing_script = git_checkout("missing-script", "missing-script-marker")?;
    let binary = xtask_binary();

    let outside_output = run_xtask(&binary, outside.path(), ["fmt"])?;
    assert!(!outside_output.status.success());
    assert_eq!(outside_output.stdout, b"");
    assert!(String::from_utf8_lossy(&outside_output.stderr).contains("inside a Git checkout"));

    let rejected_output = run_xtask(&binary, checkout.path(), ["fmt", "unexpected"])?;
    assert!(!rejected_output.status.success());
    assert_eq!(rejected_output.stdout, b"");
    assert!(String::from_utf8_lossy(&rejected_output.stderr).contains("usage: cargo xtask"));

    fs::remove_file(missing_manifest.path().join("xtask").join("Cargo.toml"))
        .map_err(|error| format!("failed to remove xtask manifest: {error}"))?;
    let missing_manifest_output = run_xtask(&binary, missing_manifest.path(), ["fmt"])?;
    assert!(!missing_manifest_output.status.success());
    assert_eq!(missing_manifest_output.stdout, b"");
    assert!(String::from_utf8_lossy(&missing_manifest_output.stderr)
        .contains("missing expected xtask manifest"));

    fs::remove_file(missing_script.path().join("scripts").join("fmt.sh"))
        .map_err(|error| format!("failed to remove fmt script: {error}"))?;
    let missing_script_output = run_xtask(&binary, missing_script.path(), ["fmt"])?;
    assert!(!missing_script_output.status.success());
    assert_eq!(missing_script_output.stdout, b"");
    assert!(String::from_utf8_lossy(&missing_script_output.stderr)
        .contains("missing expected fixed script"));

    Ok(())
}

fn xtask_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_xtask"))
}

fn git_checkout(name: &str, marker: &str) -> Result<TempTree, String> {
    let checkout = TempTree::new(name)?;
    create_minimal_checkout(checkout.path(), marker)?;
    let mut git = Command::new("git");
    clear_git_environment(&mut git);
    let output = git
        .args(["init", "--quiet"])
        .current_dir(checkout.path())
        .output()
        .map_err(|error| format!("failed to run git init: {error}"))?;
    assert!(output.status.success());
    Ok(checkout)
}

fn create_minimal_checkout(root: &Path, marker: &str) -> Result<(), String> {
    fs::create_dir_all(root.join("xtask"))
        .map_err(|error| format!("failed to create xtask dir: {error}"))?;
    fs::create_dir_all(root.join("scripts"))
        .map_err(|error| format!("failed to create scripts dir: {error}"))?;
    fs::write(
        root.join("xtask").join("Cargo.toml"),
        "[package]\nname = 'xtask'\n",
    )
    .map_err(|error| format!("failed to write xtask manifest: {error}"))?;
    for script in ["setup.sh", "fmt.sh", "ci.sh"] {
        fs::write(root.join("scripts").join(script), marker_script(marker))
            .map_err(|error| format!("failed to write {script}: {error}"))?;
    }
    Ok(())
}

fn marker_script(marker: &str) -> String {
    format!(
        "#!/bin/sh\n\
         if [ \"${{GIT_DIR-}}\" ] || [ \"${{GIT_WORK_TREE-}}\" ]; then\n\
             exit 37\n\
         fi\n\
         printf '%s\\n' '{marker}'\n"
    )
}

fn run_xtask<I, S>(binary: &Path, cwd: &Path, arguments: I) -> Result<Output, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(binary)
        .args(arguments)
        .current_dir(cwd)
        .output()
        .map_err(|error| format!("failed to run {}: {error}", binary.display()))
}

fn clear_git_environment(command: &mut Command) {
    for (key, _) in env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
}
