//! Builds the one fixed non-Rust runner pre-exec boundary.

use std::{env, error::Error, io, path::PathBuf, process::Command};

fn main() -> Result<(), Box<dyn Error>> {
    let source = "src/runner_pre_exec.c";
    println!("cargo:rerun-if-changed={source}");
    let output_directory =
        env::var_os("OUT_DIR").ok_or_else(|| io::Error::other("Cargo did not provide OUT_DIR"))?;
    let output = PathBuf::from(output_directory).join("kapsel-sandbox-runner-pre-exec");
    let compiler = env::var_os("CC").unwrap_or_else(|| "cc".into());
    let compiler_output = Command::new(&compiler).arg("--version").output()?;
    if !compiler_output.status.success() {
        return Err(io::Error::other("fixed runner compiler identity is unavailable").into());
    }
    let compiler_stdout = String::from_utf8(compiler_output.stdout)?;
    let compiler_identity = compiler_stdout
        .lines()
        .next()
        .ok_or_else(|| io::Error::other("fixed runner compiler identity is empty"))?;
    if compiler_identity.is_empty()
        || compiler_identity.len() > 128
        || !compiler_identity
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(io::Error::other("fixed runner compiler identity is invalid").into());
    }
    println!("cargo:rustc-env=KAPSEL_SANDBOX_PRE_EXEC_COMPILER={compiler_identity}");
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
