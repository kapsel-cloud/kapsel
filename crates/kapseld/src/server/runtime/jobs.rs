//! Bounded blocking-job ownership and retirement while the runtime remains driven.

use std::sync::{Arc, Mutex};

use tokio::{
    sync::{oneshot, OwnedSemaphorePermit},
    task::JoinHandle,
};

use super::{Selection, CONNECTIONS_MAX};

struct Lease {
    _connection: Arc<OwnedSemaphorePermit>,
    _execution: Option<Arc<Selection>>,
    // Dropped last, after permits. The receiver proves final shared ownership release.
    _retirement: oneshot::Sender<()>,
}

struct Job {
    supervisor: JoinHandle<()>,
    retirement: oneshot::Receiver<()>,
}

pub(super) struct Jobs(Mutex<Vec<Job>>);

impl Jobs {
    pub(super) fn new() -> Self {
        Self(Mutex::new(Vec::with_capacity(CONNECTIONS_MAX)))
    }

    /// Registers before starting work. Both supervisor and blocking closure retain the lease.
    pub(super) fn spawn(
        &self,
        connection: Arc<OwnedSemaphorePermit>,
        execution: Option<Arc<Selection>>,
        work: impl FnOnce() + Send + 'static,
    ) -> Result<(), ()> {
        let mut jobs = self.0.lock().map_err(|_| ())?;
        jobs.retain_mut(|job| {
            !job.supervisor.is_finished()
                || matches!(
                    job.retirement.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                )
        });
        if jobs.len() >= CONNECTIONS_MAX {
            return Err(());
        }
        let (retired, retirement) = oneshot::channel();
        let lease = Arc::new(Lease {
            _connection: connection,
            _execution: execution,
            _retirement: retired,
        });
        let (start, started) = oneshot::channel();
        let supervisor = tokio::spawn(async move {
            if started.await.is_err() {
                return;
            }
            let blocking_lease = lease.clone();
            let blocking = tokio::task::spawn_blocking(move || {
                let _lease = blocking_lease;
                work();
            });
            let _ = blocking.await;
            drop(lease);
        });
        jobs.push(Job {
            supervisor,
            retirement,
        });
        drop(jobs);
        let _ = start.send(());
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn first_supervisor(&self) -> Option<tokio::task::AbortHandle> {
        self.0
            .lock()
            .ok()?
            .first()
            .map(|job| job.supervisor.abort_handle())
    }

    /// Call only after accepting has stopped and all handlers have returned. Do not abort jobs.
    pub(super) async fn drain(&self) {
        // Poison cannot justify skipping retirement of handles already in the registry.
        let jobs = std::mem::take(
            &mut *self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for job in jobs {
            let _ = job.supervisor.await;
            // An aborted supervisor can leave its blocking closure alive. Wait for that too.
            let _ = job.retirement.await;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "controlled ownership fixtures")]
mod tests {
    use std::time::Duration;

    use tokio::{sync::Semaphore, time::timeout};

    use super::*;

    #[test]
    fn supervisor_abort_keeps_permits_until_blocking_work_retires() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let jobs = Jobs::new();
            let connections = Arc::new(Semaphore::new(1));
            let execution = Arc::new(Semaphore::new(1));
            let (entered, ready) = oneshot::channel();
            let (release, blocked) = std::sync::mpsc::channel();
            jobs.spawn(
                Arc::new(connections.clone().try_acquire_owned().unwrap()),
                Some(Arc::new(Selection {
                    operation_id: "job-op".into(),
                    _permit: execution.clone().try_acquire_owned().unwrap(),
                })),
                move || {
                    let _ = entered.send(());
                    let _ = blocked.recv();
                },
            )
            .unwrap();
            ready.await.unwrap();
            jobs.0.lock().unwrap()[0].supervisor.abort();
            let drain = jobs.drain();
            tokio::pin!(drain);
            assert!(timeout(Duration::from_millis(20), &mut drain)
                .await
                .is_err());
            assert_eq!(connections.available_permits(), 0);
            assert_eq!(execution.available_permits(), 0);
            release.send(()).unwrap();
            timeout(Duration::from_secs(1), drain).await.unwrap();
            assert_eq!(connections.available_permits(), 1);
            assert_eq!(execution.available_permits(), 1);
        });
    }

    #[test]
    fn abandoned_reads_stay_bounded_and_hold_connection_capacity() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let jobs = Jobs::new();
            let connections = Arc::new(Semaphore::new(CONNECTIONS_MAX));
            let mut releases = Vec::new();
            for _ in 0..CONNECTIONS_MAX {
                let (entered, ready) = oneshot::channel();
                let (release, blocked) = std::sync::mpsc::channel();
                releases.push(release);
                jobs.spawn(
                    Arc::new(connections.clone().try_acquire_owned().unwrap()),
                    None,
                    move || {
                        let _ = entered.send(());
                        let _ = blocked.recv();
                    },
                )
                .unwrap();
                ready.await.unwrap();
            }
            for job in jobs.0.lock().unwrap().iter() {
                job.supervisor.abort();
            }
            assert!(connections.clone().try_acquire_owned().is_err());
            assert_eq!(jobs.0.lock().unwrap().len(), CONNECTIONS_MAX);
            let drain = jobs.drain();
            tokio::pin!(drain);
            assert!(timeout(Duration::from_millis(20), &mut drain)
                .await
                .is_err());
            for release in releases {
                release.send(()).unwrap();
            }
            timeout(Duration::from_secs(1), drain).await.unwrap();
            assert_eq!(connections.available_permits(), CONNECTIONS_MAX);
        });
    }

    #[test]
    fn completed_jobs_are_reaped_across_repeated_selections() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let jobs = Jobs::new();
            let connections = Arc::new(Semaphore::new(1));
            for _ in 0..CONNECTIONS_MAX * 3 {
                jobs.spawn(
                    Arc::new(connections.clone().try_acquire_owned().unwrap()),
                    None,
                    || {},
                )
                .unwrap();
                timeout(Duration::from_secs(1), async {
                    while connections.available_permits() == 0 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                assert!(jobs.0.lock().unwrap().len() <= CONNECTIONS_MAX);
            }
            jobs.drain().await;
            assert!(jobs.0.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn publication_precedes_work_and_drain_keeps_the_reactor_driven() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let jobs = Arc::new(Jobs::new());
            let connections = Arc::new(Semaphore::new(1));
            let worker_jobs = jobs.clone();
            let runtime = tokio::runtime::Handle::current();
            let (entered, ready) = oneshot::channel();
            let (release, blocked) = std::sync::mpsc::channel();
            jobs.spawn(
                Arc::new(connections.clone().try_acquire_owned().unwrap()),
                None,
                move || {
                    let count = worker_jobs.0.lock().unwrap().len();
                    let _ = entered.send(count);
                    let _ = blocked.recv();
                    runtime.block_on(async {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    });
                },
            )
            .unwrap();
            assert_eq!(ready.await.unwrap(), 1);
            let drain = jobs.drain();
            tokio::pin!(drain);
            assert!(timeout(Duration::from_millis(20), &mut drain)
                .await
                .is_err());
            release.send(()).unwrap();
            timeout(Duration::from_secs(1), drain).await.unwrap();
            assert_eq!(connections.available_permits(), 1);
        });
    }
}
