//! Arbitrary bytes as decrypted vault JSON. Parsing must never panic, and
//! anything that parses must survive a serialize/parse round trip unchanged
//! (including unknown fields kept in `extra`).
#![no_main]

use aegis_core::PasswordList;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(list) = PasswordList::from_json(data) else {
        return;
    };
    let json = list.to_json().expect("a parsed list must serialize");
    let again = PasswordList::from_json(&json).expect("serialized list must parse");
    assert_eq!(
        serde_json::to_value(&list).unwrap(),
        serde_json::to_value(&again).unwrap()
    );
});
