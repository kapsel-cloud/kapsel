//! Regenerate deterministic seeds, or check them without modifying source.

use std::{env, fs, path::Path};

fn main() {
    let check_only = match env::args().nth(1).as_deref() {
        None => false,
        Some("--check") => true,
        _ => panic!("usage: seed_corpus [--check]"),
    };

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    for target in kapsel_fuzz::TARGETS {
        let directory = root.join(target);
        if !check_only {
            fs::create_dir_all(&directory).unwrap();
        }

        for (name, bytes) in kapsel_fuzz::fixtures::seeds(target) {
            let path = directory.join(name);
            if check_only {
                assert_eq!(fs::read(&path).unwrap(), bytes, "{}", path.display());
            } else {
                fs::write(path, bytes).unwrap();
            }
        }
    }
}
