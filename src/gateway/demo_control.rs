//! Compile-time-gated process checkpoints for the release-owned crash demonstration.
//!
//! This module is absent from ordinary builds. It is not an agent, command, or public Rust
//! interface and accepts only the two KAP-0038 demonstration seams.

use std::path::PathBuf;

use super::receipt::publication;

const CONTROL_DIRECTORY_ENV: &str = "KAPSEL_DEMO_CONTROL_DIRECTORY";
const PAUSE_ENV: &str = "KAPSEL_DEMO_PAUSE";
const AFTER_APPLY: &str = "after_apply";
const AFTER_RECEIPT_PUBLISH: &str = "after_receipt_publish";

pub(super) fn checkpoint_after_apply() -> Result<(), ()> {
    let Some((control, selected)) = control_configuration()? else {
        return Ok(());
    };
    create_marker(&control, "provider-apply-count", b"1")?;
    if selected == AFTER_APPLY {
        create_marker(&control, "after-apply.ready", b"after_apply")?;
        park_until_terminated();
    }
    Ok(())
}

pub(super) fn checkpoint_after_receipt_publish() -> Result<(), ()> {
    let Some((control, selected)) = control_configuration()? else {
        return Ok(());
    };
    if selected == AFTER_RECEIPT_PUBLISH {
        create_marker(
            &control,
            "after-receipt-publish.ready",
            b"after_receipt_publish",
        )?;
        park_until_terminated();
    }
    Ok(())
}

fn control_configuration() -> Result<Option<(PathBuf, String)>, ()> {
    let pause = std::env::var(PAUSE_ENV).ok();
    let directory = std::env::var_os(CONTROL_DIRECTORY_ENV).map(PathBuf::from);
    match (pause, directory) {
        (None, None) => Ok(None),
        (Some(pause), Some(directory))
            if matches!(pause.as_str(), AFTER_APPLY | AFTER_RECEIPT_PUBLISH) =>
        {
            if !directory.is_absolute() {
                return Err(());
            }
            publication::validate_private_directory(&directory).map_err(|_| ())?;
            Ok(Some((directory, pause)))
        },
        _ => Err(()),
    }
}

fn create_marker(directory: &std::path::Path, name: &str, bytes: &[u8]) -> Result<(), ()> {
    publication::create_private_file(&directory.join(name), bytes).map_err(|_| ())
}

fn park_until_terminated() -> ! {
    loop {
        std::thread::park();
    }
}
