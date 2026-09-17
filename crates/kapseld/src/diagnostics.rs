//! Best-effort fixed codes, with no sink waiting, buffering, retry or delivery promise.

use std::sync::{
    atomic::{AtomicU8, Ordering},
    OnceLock,
};

use kapsel::ServiceError;
use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{fcntl_getfl, fcntl_setfl, fstat, FileType, OFlags},
    io::{fcntl_dupfd_cloexec, write},
};

static STDERR: OnceLock<OwnedFd> = OnceLock::new();

pub(crate) fn initialize() {
    if let Some(fd) = prepare(std::io::stderr()) {
        let _ = STDERR.set(fd);
    }
}

fn prepare(fd: impl AsFd) -> Option<OwnedFd> {
    let fd = fcntl_dupfd_cloexec(fd, 3).ok()?;
    // O_NONBLOCK does not bound regular-file I/O. Only the selected journal socket or a pipe
    // can be used. The inherited open-file description is process-owned and stays nonblocking.
    if !matches!(
        FileType::from_raw_mode(fstat(&fd).ok()?.st_mode),
        FileType::Socket | FileType::Fifo
    ) {
        return None;
    }
    let flags = fcntl_getfl(&fd).ok()?;
    fcntl_setfl(&fd, flags | OFlags::NONBLOCK).ok()?;
    Some(fd)
}

pub(crate) fn emit(code: &'static str) {
    if let Some(fd) = STDERR.get() {
        emit_to(fd, code);
    }
}

fn emit_to(fd: &OwnedFd, code: &'static str) {
    let mut line = [0_u8; 64];
    if code.len() > 54 {
        return;
    }
    line[..9].copy_from_slice(b"kapseld: ");
    let end = 9 + code.len();
    line[9..end].copy_from_slice(code.as_bytes());
    line[end] = b'\n';
    // One nonblocking syscall. In particular, do not use stderr's userspace lock or write_all.
    let _ = write(fd, &line[..=end]);
}

/// At most one emission attempt per read-failure class per service lifetime, across all IDs.
#[derive(Default)]
pub(crate) struct ReadFailures(AtomicU8);

impl ReadFailures {
    pub(crate) fn report(&self, error: ServiceError) {
        self.report_to(error, emit);
    }

    fn report_to(&self, error: ServiceError, emit: impl FnOnce(&'static str)) {
        let bit = match error {
            ServiceError::InvalidRequest => return,
            ServiceError::AuthorityUnavailable => 1,
            ServiceError::OperationFailure => 2,
            ServiceError::Configuration => 4,
        };
        if self.0.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
            emit(error.operator_diagnostic());
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "controlled socket fixtures"
)]
mod tests {
    use std::{
        io::{Read as _, Write as _},
        os::unix::net::UnixStream,
    };

    use super::*;

    #[test]
    fn repeated_and_concurrent_access_failures_have_a_constant_emission_bound() {
        let failures = ReadFailures::default();
        let count = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..100 {
                        for error in [
                            ServiceError::AuthorityUnavailable,
                            ServiceError::OperationFailure,
                            ServiceError::Configuration,
                            ServiceError::InvalidRequest,
                        ] {
                            failures.report_to(error, |_| {
                                count.fetch_add(1, Ordering::Relaxed);
                            });
                        }
                    }
                });
            }
        });
        assert_eq!(count.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn full_or_closed_socket_never_waits_and_unsupported_sinks_are_skipped() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let fd = prepare(&writer).unwrap();
        let mut filled = 0;
        loop {
            match writer.write(&[b'x'; 4096]) {
                Ok(count) => filled += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("fixture fill failed: {error}"),
            }
            assert!(filled < 16 * 1024 * 1024);
        }
        emit_to(&fd, "signing_unavailable");
        let mut received = vec![0; filled];
        reader.read_exact(&mut received).unwrap();
        assert!(received.iter().all(|byte| *byte == b'x'));
        emit_to(&fd, "signing_unavailable");
        let mut line = [0; 29];
        reader.read_exact(&mut line).unwrap();
        assert_eq!(&line, b"kapseld: signing_unavailable\n");
        drop(reader);
        emit_to(&fd, "signing_unavailable");
        assert!(prepare(std::fs::File::open("/dev/null").unwrap()).is_none());
        let regular =
            std::fs::File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
        assert!(prepare(regular).is_none());
    }
}
