//! Repository-local Git hook installer.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const PRE_COMMIT_HOOK: &str = "#!/bin/sh\nset -eu\n\ncargo make fmt-check\n";

#[derive(Clone, Copy)]
enum Mode {
    Install,
    Uninstall,
}

fn main() -> ExitCode {
    match run(env::args_os()) {
        Ok(message) => report(&message, ExitCode::SUCCESS),
        Err(error) => report(&format!("hooks: {error}"), ExitCode::FAILURE),
    }
}

fn run(arguments: impl IntoIterator<Item = OsString>) -> io::Result<String> {
    let mut arguments = arguments.into_iter();
    let program = arguments
        .next()
        .unwrap_or_else(|| OsString::from("kapsel-hooks"));
    let mode_argument = arguments.next();
    let mode = parse_mode(mode_argument.as_deref(), &program)?;
    if arguments.next().is_some() {
        return Err(invalid_arguments(&program));
    }

    let hooks_dir = discover_hooks_dir()?;
    match mode {
        Mode::Install => install(&hooks_dir),
        Mode::Uninstall => uninstall(&hooks_dir),
    }
}

fn parse_mode(argument: Option<&OsStr>, program: &OsString) -> io::Result<Mode> {
    match argument.and_then(OsStr::to_str) {
        Some("install") => Ok(Mode::Install),
        Some("uninstall") => Ok(Mode::Uninstall),
        _ => Err(invalid_arguments(program)),
    }
}

fn invalid_arguments(program: &OsString) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("usage: {} [install|uninstall]", program.to_string_lossy()),
    )
}

fn discover_hooks_dir() -> io::Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-path", "hooks"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(
            "cannot find Git hooks directory; run inside a Git repository",
        ));
    }

    let path = String::from_utf8(output.stdout)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Git returned a non-UTF-8 path"))?;
    let path = path.trim();
    if path.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Git returned an empty hooks path",
        ));
    }
    Ok(PathBuf::from(path))
}

fn install(hooks_dir: &Path) -> io::Result<String> {
    fs::create_dir_all(hooks_dir)?;
    let hook_path = hooks_dir.join("pre-commit");
    fs::write(&hook_path, PRE_COMMIT_HOOK)?;
    make_executable(&hook_path)?;
    Ok(format!("hooks: installed {}", hook_path.display()))
}

fn uninstall(hooks_dir: &Path) -> io::Result<String> {
    let hook_path = hooks_dir.join("pre-commit");
    match fs::remove_file(&hook_path) {
        Ok(()) => Ok(format!("hooks: removed {}", hook_path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(format!("hooks: {} not present", hook_path.display()))
        },
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn make_executable(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(permissions.mode() | 0o111);
    fs::set_permissions(path, permissions)
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn report(message: &str, exit_code: ExitCode) -> ExitCode {
    let _ = writeln!(io::stderr().lock(), "{message}");
    exit_code
}

#[cfg(test)]
mod tests {
    use super::{install, uninstall, PRE_COMMIT_HOOK};
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> io::Result<Self> {
            let id = DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("kapsel-hooks-{}-{id}", std::process::id()));
            fs::create_dir_all(&path)?;
            Ok(Self(path))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn install_writes_canonical_pre_commit_hook() -> io::Result<()> {
        let directory = TestDirectory::create()?;

        install(directory.path())?;
        install(directory.path())?;

        let hook_path = directory.path().join("pre-commit");
        assert_eq!(fs::read_to_string(&hook_path)?, PRE_COMMIT_HOOK);
        assert!(is_executable(&hook_path)?);
        Ok(())
    }

    #[test]
    fn uninstall_removes_hook_and_is_idempotent() -> io::Result<()> {
        let directory = TestDirectory::create()?;
        install(directory.path())?;

        uninstall(directory.path())?;
        uninstall(directory.path())?;

        assert!(!directory.path().join("pre-commit").exists());
        Ok(())
    }

    #[cfg(unix)]
    fn is_executable(path: &Path) -> io::Result<bool> {
        use std::os::unix::fs::PermissionsExt;

        Ok(fs::metadata(path)?.permissions().mode() & 0o111 != 0)
    }

    #[cfg(not(unix))]
    fn is_executable(_path: &Path) -> io::Result<bool> {
        Ok(true)
    }
}
