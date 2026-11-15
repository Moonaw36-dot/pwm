//! Untrusted-input robustness: truncated, bit-flipped and random vault files
//! must make `format::open` return an error, never panic, hang or OOM.
//!
//! Inputs are generated from a fixed-seed PRNG so failures are reproducible.
//! KDF costs in mutated v2 headers are forced small (when they are within the
//! accepted bounds) so the test exercises the parser rather than Argon2; costs
//! outside the bounds are kept so validation is exercised too.

use aegis_core::format::{self, HEADER_LEN_V2, KdfParams, MAGIC};
use aegis_core::{PasswordList, UnlockedVault};

const PLAIN: &[u8] = include_bytes!("fixtures/v2_plain.aegis");
const WITH_KEYFILE: &[u8] = include_bytes!("fixtures/v2_keyfile.aegis");
const KEYFILE: &[u8] = include_bytes!("fixtures/keyfile.bin");
const PASSWORD: &str = "fixture-master";

/// Byte offset of `m_cost` in a v2 header; `t_cost` and `p_cost` follow.
const COSTS_OFFSET: usize = MAGIC.len() + 1 + format::SALT_LEN;

/// xorshift64*: tiny, deterministic, good enough for test input generation.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

fn costs(data: &[u8]) -> Option<KdfParams> {
    let word = |i: usize| {
        let at = COSTS_OFFSET + 4 * i;
        data.get(at..at + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    Some(KdfParams {
        m_cost: word(0)?,
        t_cost: word(1)?,
        p_cost: word(2)?,
    })
}

/// Rewrite in-range KDF costs in a v2 header to cheap but still valid ones.
fn shrink_costs(data: &mut [u8]) {
    if !data.starts_with(&MAGIC) {
        return;
    }
    let Some(p) = costs(data) else { return };
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

/// Feed one untrusted buffer through every entry point that is cheap enough
/// to call on arbitrary input. Returns whether `open` succeeded.
fn exercise(data: &[u8], keyfile: Option<&[u8]>) -> bool {
    let _ = format::read_salt(data);
    for attempt in format::legacy_attempts(data) {
        assert!(attempt.ciphertext_offset < data.len());
        assert!(!attempt.params.is_empty());
    }
    if data.starts_with(&MAGIC) {
        if let Ok(h) = format::parse_header_v2(data) {
            format::validate_kdf_params(h.params).unwrap();
        }
        // Only v2 files reach Argon2 with header-chosen (here: small) costs;
        // the legacy layouts always use fixed 19-64 MiB costs, which would
        // make this test crawl, so those are covered by `legacy_attempts`.
        let opened = format::open(data, PASSWORD, keyfile);
        if let Ok(o) = &opened {
            let _ = PasswordList::from_json(&o.plaintext);
        }
        opened.is_ok()
    } else if data.len() < format::SALT_LEN + 12 {
        // Too short for any legacy layout: rejected before any KDF run.
        assert!(format::open(data, PASSWORD, keyfile).is_err());
        false
    } else {
        false
    }
}

#[test]
fn every_truncation_is_rejected() {
    for (fixture, keyfile) in [(PLAIN, None), (WITH_KEYFILE, Some(KEYFILE))] {
        let mut lengths: Vec<usize> = (0..=HEADER_LEN_V2 + 20).collect();
        lengths.extend((HEADER_LEN_V2 + 20..fixture.len()).step_by(97));
        lengths.push(fixture.len() - 1);
        for len in lengths {
            // Real (unshrunk) costs: the fixture uses m=1024, t=1.
            assert!(
                format::open(&fixture[..len], PASSWORD, keyfile).is_err(),
                "truncated to {len} bytes but opened"
            );
        }
    }
}

#[test]
fn every_header_bit_flip_is_rejected() {
    // Every header byte of the plain fixture, every third one of the keyfile
    // fixture: each open runs Argon2 at the fixture's real 1 MiB cost.
    for (fixture, keyfile, stride) in [(PLAIN, None, 1), (WITH_KEYFILE, Some(KEYFILE), 3)] {
        // Bytes 0..4 are the magic: flipping one turns the file into a
        // "legacy" layout guess, which runs Argon2 at fixed 19-64 MiB costs
        // (slow in a debug test build). Those are covered by `legacy_attempts`
        // in `mutated_fixtures_do_not_panic`.
        for byte in (MAGIC.len()..HEADER_LEN_V2).step_by(stride) {
            for bit in 0..8 {
                let mut data = fixture.to_vec();
                data[byte] ^= 1 << bit;
                // A flipped cost bit can raise m_cost to 1 GiB or t_cost to
                // 20; those headers are valid but too slow for a unit test.
                // Any change to salt or costs changes the derived key anyway.
                if let Some(p) = costs(&data)
                    && format::validate_kdf_params(p).is_ok()
                    && (p.m_cost > 4096 || p.t_cost > 2 || p.p_cost > 2)
                {
                    continue;
                }
                assert!(
                    format::open(&data, PASSWORD, keyfile).is_err(),
                    "bit {bit} of header byte {byte} flipped but opened"
                );
            }
        }
    }
}

#[test]
fn ciphertext_bit_flips_are_rejected() {
    let mut rng = Rng(0x5eed_0001);
    for (fixture, keyfile) in [(PLAIN, None), (WITH_KEYFILE, Some(KEYFILE))] {
        for _ in 0..24 {
            let mut data = fixture.to_vec();
            let byte = HEADER_LEN_V2 + rng.below(fixture.len() - HEADER_LEN_V2);
            data[byte] ^= 1 << rng.below(8);
            assert!(
                format::open(&data, PASSWORD, keyfile).is_err(),
                "ciphertext byte {byte} flipped but opened"
            );
        }
    }
}

#[test]
fn mutated_fixtures_do_not_panic() {
    let mut rng = Rng(0x5eed_0002);
    for (fixture, keyfile) in [(PLAIN, None), (WITH_KEYFILE, Some(KEYFILE))] {
        for _ in 0..300 {
            let mut data = fixture.to_vec();
            for _ in 0..1 + rng.below(4) {
                match rng.below(4) {
                    0 => {
                        let i = rng.below(data.len().max(1));
                        if let Some(b) = data.get_mut(i) {
                            *b ^= 1 << rng.below(8);
                        }
                    }
                    1 => {
                        let i = rng.below(HEADER_LEN_V2);
                        if let Some(b) = data.get_mut(i) {
                            *b = rng.next() as u8;
                        }
                    }
                    2 => data.truncate(rng.below(data.len() + 1)),
                    _ => {
                        let n = rng.below(64);
                        let extra = rng.bytes(n);
                        data.extend_from_slice(&extra);
                    }
                }
            }
            shrink_costs(&mut data);
            exercise(&data, keyfile);
            exercise(&data, None);
        }
    }
}

#[test]
fn random_buffers_do_not_panic() {
    let mut rng = Rng(0x5eed_0003);
    for i in 0..1500 {
        let len = rng.below(160);
        let mut data = rng.bytes(len);
        // Half of the inputs get a v2 prefix so they get past the magic check.
        if i % 2 == 0 && data.len() >= 5 {
            data[..4].copy_from_slice(&MAGIC);
            data[4] = if rng.below(8) == 0 {
                rng.next() as u8
            } else {
                format::FORMAT_VERSION
            };
            // Sometimes plant in-range costs so validation passes.
            if data.len() >= COSTS_OFFSET + 12 && rng.below(2) == 0 {
                for (j, v) in [8 + rng.below(64) as u32, 1, 1].iter().enumerate() {
                    let at = COSTS_OFFSET + 4 * j;
                    data[at..at + 4].copy_from_slice(&v.to_le_bytes());
                }
            }
        }
        shrink_costs(&mut data);
        let keyfile = (i % 3 == 0).then_some(KEYFILE);
        assert!(!exercise(&data, keyfile), "random buffer {i} opened");
    }
}

#[test]
fn out_of_range_costs_fail_fast() {
    let cases = [
        (0, 1, 1),
        (7, 1, 1),
        (format::MAX_M_COST + 1, 1, 1),
        (u32::MAX, 1, 1),
        (1024, 0, 1),
        (1024, format::MAX_T_COST + 1, 1),
        (1024, u32::MAX, 1),
        (1024, 1, 0),
        (1024, 1, format::MAX_P_COST + 1),
        (1024, 1, u32::MAX),
        // In range individually, but Argon2 needs m_cost >= 8 * p_cost.
        (8, 1, 8),
    ];
    for (m, t, p) in cases {
        let mut data = PLAIN.to_vec();
        for (j, v) in [m, t, p].iter().enumerate() {
            let at = COSTS_OFFSET + 4 * j;
            data[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        assert!(format::open(&data, PASSWORD, None).is_err(), "{m}/{t}/{p}");
    }
}

#[test]
fn malformed_json_does_not_panic() {
    let mut rng = Rng(0x5eed_0004);
    let base = UnlockedVault::open(PLAIN, PASSWORD, None).unwrap();
    let json = base.list.to_json().unwrap().to_vec();
    for _ in 0..2000 {
        let mut data = json.clone();
        for _ in 0..1 + rng.below(3) {
            match rng.below(3) {
                0 => {
                    let i = rng.below(data.len());
                    data[i] = b"{}[]\",:0n-e."[rng.below(12)];
                }
                1 => data.truncate(rng.below(data.len() + 1)),
                _ => {
                    let i = rng.below(data.len());
                    data.remove(i);
                }
            }
            if data.is_empty() {
                break;
            }
        }
        if let Ok(list) = PasswordList::from_json(&data) {
            let again = PasswordList::from_json(&list.to_json().unwrap()).unwrap();
            assert_eq!(
                serde_json::to_value(&list).unwrap(),
                serde_json::to_value(&again).unwrap()
            );
        }
    }
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    assert!(PasswordList::from_json(deep.as_bytes()).is_err());
    let deep_extra = format!(
        r#"{{"entries":[],"x":{}0{}}}"#,
        "[".repeat(10_000),
        "]".repeat(10_000)
    );
    assert!(PasswordList::from_json(deep_extra.as_bytes()).is_err());
}

/// Found by the `vault_json` fuzz target: without serde_json's
/// `float_roundtrip` feature, float values in unknown fields drifted by an ULP
/// on every load/save cycle, so `extra` was not written back unchanged.
#[test]
fn unknown_float_fields_roundtrip_exactly() {
    let json = br#"{"entries":[{"label":"x","future":170E0000050,"f2":[0.1,1e-300,2.2250738585072014e-308]}],"m":-1.5e300}"#;
    let mut list = PasswordList::from_json(json).unwrap();
    let first = serde_json::to_value(&list).unwrap();
    for _ in 0..3 {
        list = PasswordList::from_json(&list.to_json().unwrap()).unwrap();
        assert_eq!(serde_json::to_value(&list).unwrap(), first);
    }
}
