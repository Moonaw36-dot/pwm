//! seal -> open must return the exact plaintext for any password, keyfile,
//! salt and payload, and the sealed header must parse back to its inputs.
#![no_main]

use aegis_core::format::{self, KdfParams, SALT_LEN};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    password: &'a str,
    keyfile: Option<&'a [u8]>,
    salt: [u8; SALT_LEN],
    /// Small m/t/p choices so Argon2 stays cheap.
    m_extra: u8,
    two_lanes: bool,
    plaintext: &'a [u8],
}

fuzz_target!(|input: Input| {
    let p_cost = if input.two_lanes { 2 } else { 1 };
    let params = KdfParams {
        m_cost: 8 * p_cost + u32::from(input.m_extra % 32),
        t_cost: 1,
        p_cost,
    };
    let key = format::derive_key(input.password, &input.salt, params, input.keyfile)
        .expect("in-range params must derive");
    let sealed = format::seal(input.plaintext, &key, &input.salt, params).expect("seal");

    let header = format::parse_header_v2(&sealed).expect("own header must parse");
    assert_eq!(header.salt, input.salt);
    assert_eq!(header.params, params);
    assert_eq!(format::read_salt(&sealed).unwrap(), input.salt);

    let opened = format::open_v2(&sealed, input.password, input.keyfile).expect("open_v2");
    assert_eq!(&opened.plaintext[..], input.plaintext);
    assert_eq!(*opened.key, *key);
    assert_eq!(opened.params, params);
    assert_eq!(opened.salt, input.salt);

    let via_open = format::open(&sealed, input.password, input.keyfile).expect("open");
    assert_eq!(&via_open.plaintext[..], input.plaintext);

    // Any single-bit corruption of the sealed file must be rejected. Pick the
    // position from the input so the fuzzer explores it.
    let pos = (input.m_extra as usize * 131 + input.plaintext.len()) % sealed.len();
    if pos >= format::MAGIC.len() {
        let mut bad = sealed.clone();
        bad[pos] ^= 1;
        if let Ok(h) = format::parse_header_v2(&bad) {
            // A flipped cost bit may make Argon2 expensive; skip those.
            if h.params.m_cost > 64 || h.params.t_cost > 2 {
                return;
            }
        }
        assert!(format::open(&bad, input.password, input.keyfile).is_err());
    }
});
