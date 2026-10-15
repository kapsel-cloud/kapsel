//! Bounded retirement and output for invocation-owned source-process children.

use std::{
    io::{self, Read as _, Write as _},
    ops::{Deref, DerefMut},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const DEADLINE: Duration = Duration::from_secs(10);
const OUTPUT_MAX: u64 = 256 * 1024;

pub(super) struct ChildGuard(Option<Child>);

impl ChildGuard {
    pub(super) fn new(child: Child) -> Self {
        Self(Some(child))
    }

    #[allow(dead_code, reason = "stdio bridge targets instead supply piped stdin")]
    pub(super) fn output(command: &mut Command) -> io::Result<Output> {
        Self::new(
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
        )
        .wait_with_output()
    }

    pub(super) fn wait(&mut self) -> io::Result<ExitStatus> {
        self.wait_for(DEADLINE)
    }

    pub(super) fn wait_for(&mut self, duration: Duration) -> io::Result<ExitStatus> {
        let deadline = Instant::now() + duration;
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                let _ = terminate_and_reap(self.0.as_mut().unwrap());
                return Err(io::Error::new(io::ErrorKind::TimedOut, "child retirement"));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[allow(dead_code, reason = "only stdio fixtures supply input")]
    pub(super) fn write_with_output(self, input: Vec<u8>) -> io::Result<Output> {
        self.write_with_output_for(input, DEADLINE)
    }

    #[allow(dead_code, reason = "only stdio fixtures supply input")]
    pub(super) fn write_with_output_for(
        mut self,
        input: Vec<u8>,
        duration: Duration,
    ) -> io::Result<Output> {
        let mut stdin = self.stdin.take().unwrap();
        let (send, receive) = mpsc::channel();
        thread::spawn(move || {
            let result = stdin.write_all(&input);
            drop(stdin);
            let _ = send.send(result);
        });
        let stdout = capture(self.stdout.take());
        let stderr = capture(self.stderr.take());
        // Waiting starts while the writer is active, not after a potentially blocking write.
        let status = self.wait_for(duration)?;
        receive
            .recv_timeout(duration)
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "child stdin writer"))??;
        Ok(Output {
            status,
            stdout: captured(&stdout)?,
            stderr: captured(&stderr)?,
        })
    }

    pub(super) fn wait_with_output(mut self) -> io::Result<Output> {
        self.stdin.take();
        let stdout = capture(self.stdout.take());
        let stderr = capture(self.stderr.take());
        let status = self.wait()?;
        Ok(Output {
            status,
            stdout: captured(&stdout)?,
            stderr: captured(&stderr)?,
        })
    }
}

fn capture(stream: Option<impl io::Read + Send + 'static>) -> mpsc::Receiver<io::Result<Vec<u8>>> {
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = if let Some(stream) = stream {
            stream
                .take(OUTPUT_MAX + 1)
                .read_to_end(&mut bytes)
                .and_then(|_| {
                    if bytes.len() as u64 > OUTPUT_MAX {
                        Err(io::Error::other("child output exceeds bound"))
                    } else {
                        Ok(bytes)
                    }
                })
        } else {
            Ok(bytes)
        };
        let _ = send.send(result);
    });
    receive
}

fn captured(receive: &mpsc::Receiver<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
    receive
        .recv_timeout(DEADLINE)
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "child output did not reach EOF"))?
}

fn terminate_and_reap(child: &mut Child) -> io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    let _ = child.kill();
    let deadline = Instant::now() + DEADLINE;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "child cleanup incomplete",
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

impl Deref for ChildGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

impl DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().unwrap()
    }
}

impl Drop for ChildGuard {
    #[allow(
        clippy::print_stderr,
        clippy::panic,
        reason = "incomplete fixture cleanup must fail, without double panic during unwinding"
    )]
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            if terminate_and_reap(&mut child).is_err() {
                if thread::panicking() {
                    eprintln!("source-process child retirement incomplete");
                } else {
                    panic!("source-process child retirement incomplete");
                }
            }
        }
    }
}
