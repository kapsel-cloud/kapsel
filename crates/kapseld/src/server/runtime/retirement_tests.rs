//! Ready-stop priority and physical storage/application/root/lease retirement ordering.
#![allow(
    clippy::unwrap_used,
    reason = "barrier fixture failures must fail immediately"
)]
#![allow(
    clippy::significant_drop_tightening,
    reason = "moved server state spans the complete retirement decision"
)]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Condvar,
};

use super::*;
use crate::startup::{tests::valid_root, InstallationInputs};

struct BlockedStorage {
    started: Mutex<Option<oneshot::Sender<()>>>,
    release: Arc<(Mutex<bool>, Condvar)>,
    retired: Arc<AtomicBool>,
}

impl ApplicationReads for BlockedStorage {
    fn read(&self, _: protocol::ReadRequest) -> (Vec<u8>, ResponseClass) {
        self.started
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .send(())
            .unwrap();
        let (lock, ready) = &*self.release;
        let mut released = lock.lock().unwrap();
        while !*released {
            released = ready.wait(released).unwrap();
        }
        drop(released);
        (operation_failure(), ResponseClass::Ordinary)
    }
    fn admitted_state(&self, _: &str) -> Result<Option<kapsel::OperationState>, ServiceError> {
        Ok(None)
    }
}

impl Drop for BlockedStorage {
    fn drop(&mut self) {
        assert!(*self.release.0.lock().unwrap());
        self.retired.store(true, Ordering::SeqCst);
    }
}

#[test]
fn sigterm_retains_blocked_storage_and_lease_until_ordered_retirement() {
    let root = valid_root("retirement-storage");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let inputs = InstallationInputs::open_at(&root).unwrap();
        let listener = inputs.bind_listener().unwrap();
        let (started, began) = oneshot::channel();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let retired = Arc::new(AtomicBool::new(false));
        let state = ServerState::new(
            BlockedStorage {
                started: Mutex::new(Some(started)),
                release: release.clone(),
                retired: retired.clone(),
            },
            UnavailableExecution,
        );
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        let (observed, acknowledged) = oneshot::channel();
        let checked_retired = retired.clone();
        let server = tokio::spawn(async move {
            serve_until_stopped(
                listener,
                rustix::process::getegid().as_raw(),
                state,
                None,
                async {
                    terminate.recv().await;
                    observed.send(()).unwrap();
                },
            )
            .await
            .unwrap();
            assert!(checked_retired.load(Ordering::SeqCst));
            drop(inputs);
        });
        let mut client = UnixStream::connect(root.join("run/kapsel/kapseld.sock"))
            .await
            .unwrap();
        write_response_frame(
            &mut client,
            concat!(
                r#"{"version":1,"request":"get_set_deployment_image_status","#,
                r#""operation_id":"service-op"}"#,
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        began.await.unwrap();
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
            .unwrap();
        acknowledged.await.unwrap();
        assert!(!server.is_finished());
        assert!(!retired.load(Ordering::SeqCst));
        assert!(InstallationInputs::open_at(&root).is_err());
        assert!(UnixStream::connect(root.join("run/kapsel/kapseld.sock"))
            .await
            .is_err());
        *release.0.lock().unwrap() = true;
        release.1.notify_all();
        server.await.unwrap();
        assert!(retired.load(Ordering::SeqCst));
        drop(InstallationInputs::open_at(&root).unwrap());
    });
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn ready_stop_wins_over_already_queued_connection() {
    let root = valid_root("retirement-ready-stop");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let inputs = InstallationInputs::open_at(&root).unwrap();
        let listener = inputs.bind_listener().unwrap();
        // Prime Tokio's listener readiness without consuming the request tested below.
        let probe = UnixStream::connect(root.join("run/kapsel/kapseld.sock"))
            .await
            .unwrap();
        drop(listener.accept().await.unwrap());
        drop(probe);
        let mut client = UnixStream::connect(root.join("run/kapsel/kapseld.sock"))
            .await
            .unwrap();
        write_response_frame(
            &mut client,
            concat!(
                r#"{"version":1,"request":"get_set_deployment_image_status","#,
                r#""operation_id":"service-op"}"#,
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let (started, began) = oneshot::channel();
        let retired = Arc::new(AtomicBool::new(false));
        let state = ServerState::new(
            BlockedStorage {
                started: Mutex::new(Some(started)),
                release: Arc::new((Mutex::new(true), Condvar::new())),
                retired: retired.clone(),
            },
            UnavailableExecution,
        );
        serve_until_stopped(
            listener,
            rustix::process::getegid().as_raw(),
            state,
            None,
            std::future::ready(()),
        )
        .await
        .unwrap();
        assert!(began.await.is_err());
        assert!(retired.load(Ordering::SeqCst));
        drop(inputs);
    });
    std::fs::remove_dir_all(root).unwrap();
}
