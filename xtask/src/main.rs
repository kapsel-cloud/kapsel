//! Route contributor commands to the scripts that implement their checks.
//!
//! This executable accepts a fixed set of commands and modes, then runs their shell scripts
//! from the checkout root. The scripts own the checks, not this routing layer.

use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

const FIXED_SCRIPTS: [&str; 6] = [
    "scripts/setup.sh",
    "scripts/fmt.sh",
    "scripts/ci.sh",
    "scripts/check.sh",
    "scripts/explore.sh",
    "scripts/qualify.sh",
];
const AREAS: [&str; 6] = ["authority", "core", "service", "tools", "release", "docs"];
const BOUNDARIES: [&str; 7] = [
    "storage",
    "artifact",
    "reproducibility",
    "kubernetes",
    "git",
    "native",
    "security",
];

#[allow(
    clippy::print_stderr,
    reason = "the CLI reports contributor-command failures"
)]
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
    if arguments.is_empty()
        || (arguments.len() == 1 && matches!(arguments[0].as_str(), "help" | "--help" | "-h"))
    {
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
        // Current workflows still use ci; W6 owns its final cutover.
        ["check" | "ci"] => Ok(("scripts/check.sh", vec!["check"])),
        [verb @ ("test" | "check"), area] if AREAS.contains(area) => {
            Ok(("scripts/check.sh", vec![*verb, *area]))
        },
        ["explore", mode @ ("sim" | "fuzz"), rest @ ..] => Ok((
            "scripts/explore.sh",
            std::iter::once(*mode).chain(rest.iter().copied()).collect(),
        )),
        ["qualify", boundary, rest @ ..] if BOUNDARIES.contains(boundary) => Ok((
            "scripts/qualify.sh",
            std::iter::once(*boundary)
                .chain(rest.iter().copied())
                .collect(),
        )),
        ["ci", lane @ ("static" | "rust" | "doc")] => Ok(("scripts/ci.sh", vec![*lane])),
        _ => Err(concat!(
            "usage: cargo xtask setup|doctor|fmt|test <area>|check [area]|",
            "explore sim|fuzz ...|qualify <boundary> ..."
        )
        .into()),
    }
}

#[allow(
    clippy::print_stdout,
    reason = "the CLI prints contributor-command help"
)]
fn print_help() {
    println!(
        "Contributor commands:\n\
        cargo xtask setup       install isolated pinned tools\n\
        cargo xtask doctor      diagnose tools without installing\n\
        cargo xtask fmt         format source and documentation\n\
        cargo xtask fmt-check   check formatting without rewriting\n\
        cargo xtask test <area> focused deterministic iteration\n\
        cargo xtask check [area] completed-change gate (default: all)\n\
        cargo xtask explore sim|fuzz ... explicit bounded exploration\n\
        cargo xtask qualify <boundary> ... explicit physical/selected-byte evidence\n\
        Areas: authority, core, service, tools, release, docs"
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
            (vec!["ci"], "scripts/check.sh", vec!["check"]),
            (vec!["check"], "scripts/check.sh", vec!["check"]),
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
        for area in super::AREAS {
            for verb in ["test", "check"] {
                let arguments = [verb.to_owned(), area.to_owned()];
                assert_eq!(
                    parse_command(&arguments)?,
                    ("scripts/check.sh", vec![verb, area])
                );
                assert!(
                    parse_command(&[verb.to_owned(), area.to_owned(), "extra".into()]).is_err()
                );
            }
        }
        for (verb, mode, script) in [
            ("explore", "sim", "scripts/explore.sh"),
            ("explore", "fuzz", "scripts/explore.sh"),
            ("qualify", "artifact", "scripts/qualify.sh"),
            ("qualify", "storage", "scripts/qualify.sh"),
            ("qualify", "reproducibility", "scripts/qualify.sh"),
            ("qualify", "kubernetes", "scripts/qualify.sh"),
            ("qualify", "git", "scripts/qualify.sh"),
            ("qualify", "native", "scripts/qualify.sh"),
            ("qualify", "security", "scripts/qualify.sh"),
        ] {
            let arguments = [
                verb.into(),
                mode.into(),
                "--output".into(),
                "path with space".into(),
            ];
            assert_eq!(
                parse_command(&arguments)?,
                (script, vec![mode, "--output", "path with space"])
            );
        }
        for values in [
            vec!["test"],
            vec!["check", "all"],
            vec!["explore", "unknown"],
            vec!["qualify", "unknown"],
        ] {
            let arguments = values.into_iter().map(String::from).collect::<Vec<_>>();
            assert!(parse_command(&arguments).is_err());
        }
        assert!(parse_command(&["ci".into(), "live".into()]).is_err());
        Ok(())
    }
}
