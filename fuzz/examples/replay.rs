//! Replay one explicitly selected bounded input through the same semantic fuzz driver.

use std::{env, fs::File, io::Read};

fn main() {
    let arguments: Vec<_> = env::args().skip(1).collect();
    assert_eq!(arguments.len(), 2, "usage: replay TARGET INPUT");
    assert!(
        kapsel_fuzz::TARGETS.contains(&arguments[0].as_str()),
        "unknown target"
    );
    let mut bytes = Vec::new();
    File::open(&arguments[1])
        .unwrap()
        .take(160 * 1024 + 2)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 160 * 1024 + 1, "replay input bound");
    kapsel_fuzz::run(&arguments[0], &bytes);
}
