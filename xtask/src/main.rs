//! Contributor command routing; tooling implementations retain their direct owners.
//!
//! This crate does not own release verification or live qualification. It invokes
//! the existing shell commands from the checkout root without interpreting argv.

use std::{
    env,
    path::Path,
    process::{Command, ExitCode},
};

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
    let (script, arguments) = command(&arguments)?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask must live beneath the checkout root")?;
    let status = Command::new("sh")
        .arg(root.join(script))
        .args(arguments)
        .current_dir(root)
        .status()
        .map_err(|error| format!("failed to run {script}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{script} failed: {status}"))
    }
}

fn command(arguments: &[String]) -> Result<(&'static str, Vec<&str>), String> {
    let values: Vec<_> = arguments.iter().map(String::as_str).collect();
    match values.as_slice() {
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
    use super::command;

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
            assert_eq!(command(&arguments)?, (script, expected));
            let mut extra = arguments;
            extra.push("unexpected".into());
            assert!(command(&extra).is_err());
        }
        assert!(command(&["ci".into(), "live".into()]).is_err());
        Ok(())
    }
}
