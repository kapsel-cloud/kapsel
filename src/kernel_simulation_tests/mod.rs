//! Actual application histories with independent intent, I/O, retained-fact and progress laws.

mod cases;
mod exploration;
mod laws;
mod run;
mod trace;
mod world;

pub(crate) use run::executed_write_statements;

#[tokio::test(start_paused = true)]
#[ignore = "explicit bounded replay input or private evidence directory required"]
async fn kernel_trace_exploration_or_replay() {
    exploration::explore_or_replay().await;
}
