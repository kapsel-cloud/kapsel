#![no_main]

use kapsel::{inspect_receipt, InspectionLimits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let Some(selector) = input.get(..4) else {
        return;
    };
    let documents = &input[4..];
    let split = usize::try_from(u32::from_be_bytes(selector.try_into().unwrap())).unwrap()
        % (documents.len() + 1);
    let (receipt, trust) = documents.split_at(split);

    let _ = inspect_receipt(receipt, trust, 150, InspectionLimits::default());
});
