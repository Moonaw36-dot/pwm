//! Arbitrary bytes as a vault file: parsing must never panic, hang or OOM.
//!
//! Argon2 would dominate every execution at real costs, so in-range KDF costs
//! in a v2 header are rewritten to tiny valid ones before calling `open`
//! (out-of-range costs are kept, to exercise validation). Files without the
//! v2 magic would run Argon2 at fixed 19-64 MiB legacy costs, so for those
//! only the pure layout parsing (`read_salt`, `legacy_attempts`) is fuzzed.
#![no_main]

use aegis_core::PasswordList;
use aegis_core::format::{self, KdfParams, MAGIC, SALT_LEN};
use libfuzzer_sys::fuzz_target;

const KEYFILE: &[u8] = b"fixed fuzz keyfile, 32 bytes!!!!";
const COSTS_OFFSET: usize = MAGIC.len() + 1 + SALT_LEN;

fn word(data: &[u8], i: usize) -> u32 {
    let at = COSTS_OFFSET + 4 * i;
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

fn shrink_costs(data: &mut [u8]) {
    if !data.starts_with(&MAGIC) || data.len() < COSTS_OFFSET + 12 {
        return;
    }
    let p = KdfParams {
        m_cost: word(data, 0),
        t_cost: word(data, 1),
        p_cost: word(data, 2),
    };
    if format::validate_kdf_params(p).is_err() {
        return;
    }
    let p_cost = 1 + p.p_cost % 2;
    let small = [8 * p_cost + p.m_cost % 32, 1 + p.t_cost % 2, p_cost];
    for (i, v) in small.iter().enumerate() {
        let at = COSTS_OFFSET + 4 * i;
        data[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
}

fuzz_target!(|input: &[u8]| {
    let mut data = input.to_vec();
    shrink_costs(&mut data);

    let _ = format::read_salt(&data);
    for attempt in format::legacy_attempts(&data) {
        assert!(attempt.ciphertext_offset < data.len());
        assert!(!attempt.params.is_empty());
    }

    if !data.starts_with(&MAGIC) {
        if data.len() <= format::HEADER_LEN_LEGACY {
            // No legacy layout fits: rejected without any key derivation.
            assert!(format::open(&data, "pw", None).is_err());
        }
        return;
    }

    if let Ok(header) = format::parse_header_v2(&data) {
        format::validate_kdf_params(header.params).unwrap();
        assert!(header.params.m_cost <= 8 * 2 + 31 && header.params.t_cost <= 2);
    }
    for keyfile in [None, Some(KEYFILE)] {
        if let Ok(opened) = format::open(&data, "pw", keyfile) {
            let _ = PasswordList::from_json(&opened.plaintext);
        }
    }
});
