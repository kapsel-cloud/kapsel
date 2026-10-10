//! Route contributor commands to the scripts that implement their checks.
//!
//! This crate accepts a fixed set of commands and modes, then runs their shell scripts
//! from the checkout root. The scripts own the checks, not this routing layer.

use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

const FIXED_SCRIPTS: [&str; 3] = ["scripts/setup.sh", "scripts/fmt.sh", "scripts/ci.sh"];

#[allow(clippy::print_stderr)]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    if arguments.is_empty() || matches!(arguments[0].as_str(), "help" | "--help" | "-h") {
        print_help();
        return Ok(());
    }

    let (script, script_arguments) = parse_command(&arguments)?;
    let root = invocation_checkout_root()?;

    let mut shell = Command::new("sh");
    clear_git_environment(&mut shell);
    let status = shell
        .arg(root.join(script))
        .args(script_arguments)
        .current_dir(root)
        .status()
        .map_err(|error| format!("failed to run {script}: {error}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("{script} failed: {status}"))
    }
}

fn invocation_checkout_root() -> Result<PathBuf, String> {
    let invocation_directory =
        env::current_dir().map_err(|error| format!("failed to read current dir: {error}"))?;
    let mut git = Command::new("git");
    clear_git_environment(&mut git);
    let output = git
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(&invocation_directory)
        .output()
        .map_err(|error| format!("failed to locate Git checkout root: {error}"))?;
    if !output.status.success() {
        return Err("cargo xtask must run from inside a Git checkout".into());
    }

    let root_output = String::from_utf8(output.stdout)
        .map_err(|error| format!("Git checkout root was not valid UTF-8: {error}"))?;
    let mut lines = root_output.lines();
    let root = lines
        .next()
        .ok_or("Git did not report a checkout root")?
        .to_owned();
    if root.is_empty() || lines.next().is_some() {
        return Err("Git reported an ambiguous checkout root".into());
    }

    let root = PathBuf::from(root);
    validate_checkout_root(&root)?;
    Ok(root)
}

fn clear_git_environment(command: &mut Command) {
    for (key, _) in env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
}

fn validate_checkout_root(root: &Path) -> Result<(), String> {
    let manifest = root.join("xtask").join("Cargo.toml");
    if !manifest.is_file() {
        return Err(format!(
            "Git checkout root is missing expected xtask manifest: {}",
            manifest.display()
        ));
    }

    for script in FIXED_SCRIPTS {
        let path = root.join(script);
        if !path.is_file() {
            return Err(format!(
                "Git checkout root is missing expected fixed script: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn parse_command(arguments: &[String]) -> Result<(&'static str, Vec<&str>), String> {
    let argument_values: Vec<_> = arguments.iter().map(String::as_str).collect();
    match argument_values.as_slice() {
        ["setup"] => Ok(("scripts/setup.sh", vec![])),
        ["doctor"] => Ok(("scripts/setup.sh", vec!["--check"])),
        ["fmt"] => Ok(("scripts/fmt.sh", vec![])),
        ["fmt-check"] => Ok(("scripts/fmt.sh", vec!["--check"])),
        ["ci"] => Ok(("scripts/ci.sh", vec![])),
        ["ci", lane @ ("static" | "rust" | "doc")] => Ok(("scripts/ci.sh", vec![*lane])),
        _ => Err("usage: cargo xtask <setup|doctor|fmt|fmt-check|ci [static|rust|doc]>".into()),
    }
}

#[allow(clippy::print_stdout)]
fn print_help() {
    println!(
        "Contributor commands:\n\
        cargo xtask setup       install isolated pinned tools\n\
        cargo xtask doctor      diagnose tools without installing\n\
        cargo xtask fmt         format source and documentation\n\
        cargo xtask fmt-check   check formatting without rewriting\n\
        cargo xtask ci          run the deterministic gate\n\
        cargo xtask ci <lane>   run static, rust, or doc checks"
    );
}

#[cfg(test)]
mod tests {
    use super::parse_command;

    #[test]
    fn commands_preserve_modes_and_reject_extra_arguments() -> Result<(), String> {
        for (values, script, expected) in [
            (vec!["setup"], "scripts/setup.sh", vec![]),
            (vec!["doctor"], "scripts/setup.sh", vec!["--check"]),
            (vec!["fmt"], "scripts/fmt.sh", vec![]),
            (vec!["fmt-check"], "scripts/fmt.sh", vec!["--check"]),
            (vec!["ci"], "scripts/ci.sh", vec![]),
            (vec!["ci", "static"], "scripts/ci.sh", vec!["static"]),
            (vec!["ci", "rust"], "scripts/ci.sh", vec!["rust"]),
            (vec!["ci", "doc"], "scripts/ci.sh", vec!["doc"]),
        ] {
            let arguments = values.iter().map(ToString::to_string).collect::<Vec<_>>();
            assert_eq!(parse_command(&arguments)?, (script, expected));

            let mut extra_arguments = arguments;
            extra_arguments.push("unexpected".into());
            assert!(parse_command(&extra_arguments).is_err());
        }
        assert!(parse_command(&["ci".into(), "live".into()]).is_err());
        Ok(())
    }
}
