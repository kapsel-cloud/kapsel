//! Builds the one fixed non-Rust runner pre-exec boundary.

use std::{env, error::Error, io, path::PathBuf, process::Command};

fn main() -> Result<(), Box<dyn Error>> {
    let source = "src/runner_pre_exec.c";
    println!("cargo:rerun-if-changed={source}");
    let output_directory =
        env::var_os("OUT_DIR").ok_or_else(|| io::Error::other("Cargo did not provide OUT_DIR"))?;
    let output = PathBuf::from(output_directory).join("kapsel-sandbox-runner-pre-exec");
    let compiler = env::var_os("CC").unwrap_or_else(|| "cc".into());
    let status = Command::new(compiler)
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .arg("-o")
        .arg(&output)
        .status()?;
    if !status.success() {
        return Err(io::Error::other("fixed runner pre-exec helper did not compile").into());
    }
    println!(
        "cargo:rustc-env=KAPSEL_SANDBOX_RUNNER_PRE_EXEC={}",
        output.display()
    );
    Ok(())
}
