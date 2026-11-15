//! Vault file format and crypto.
//!
//! Everything here works on bytes so it can run unchanged on desktop and
//! mobile: callers do their own file I/O and (de)serialization.
//!
//! Current layout (format v2), all integers little-endian:
//!
//! ```text
//! "AEGS" | version u8 | salt [16] | m_cost u32 | t_cost u32 | p_cost u32 | nonce [12] | AES-256-GCM ciphertext
//! ```
//!
//! The whole header is authenticated as AAD. Older headerless layouts are
//! still accepted by [`open`].

use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use argon2::Argon2;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const MAGIC: [u8; 4] = *b"AEGS";
pub const FORMAT_VERSION: u8 = 2;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;
const ITER_LEN: usize = 4;
/// Pre-v2 layout with an iteration count: `salt | t_cost u32 | nonce | ct`.
pub const HEADER_LEN: usize = SALT_LEN + ITER_LEN + NONCE_LEN;
/// Oldest layout: `salt | nonce | ct`.
pub const HEADER_LEN_LEGACY: usize = SALT_LEN + NONCE_LEN;
pub const HEADER_LEN_V2: usize = MAGIC.len() + 1 + SALT_LEN + 12 + NONCE_LEN;

pub const DEFAULT_M_COST: u32 = 65536;
pub const DEFAULT_T_COST: u32 = 3;
/// Bounds on KDF parameters read from the vault header, which is untrusted
/// input: absurd values must fail fast instead of hanging or OOMing.
pub const MIN_M_COST: u32 = 8;
pub const MAX_M_COST: u32 = 1_048_576;
pub const MAX_T_COST: u32 = 20;
pub const MAX_P_COST: u32 = 8;

pub type Key = Zeroizing<[u8; KEY_LEN]>;

const DECRYPT_ERROR: &str = "Decryption failed: wrong master password or corrupted file";
const TRUNCATED: &str = "Vault file is truncated or corrupted";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: DEFAULT_M_COST,
            t_cost: DEFAULT_T_COST,
            p_cost: 1,
        }
    }
}

pub fn validate_kdf_params(params: KdfParams) -> Result<(), String> {
    if !(MIN_M_COST..=MAX_M_COST).contains(&params.m_cost)
        || !(1..=MAX_T_COST).contains(&params.t_cost)
        || !(1..=MAX_P_COST).contains(&params.p_cost)
    {
        return Err("Vault file is corrupted".to_string());
    }
    Ok(())
}

/// Raw Argon2id output before any keyfile is mixed in.
pub fn argon2_key(password: &str, salt: &[u8; SALT_LEN], params: KdfParams) -> Result<Key, String> {
    let mut key: Key = Zeroizing::new([0u8; KEY_LEN]);
    let argon_params = argon2::Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| format!("Argon2 params: {e}"))?;
    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    )
    .hash_password_into(password.as_bytes(), salt, &mut *key)
    .map_err(|e| format!("Key derivation failed: {e}"))?;
    Ok(key)
}

/// Derive the vault key from the password, and the keyfile when one is used.
pub fn derive_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
    keyfile: Option<&[u8]>,
) -> Result<Key, String> {
    validate_kdf_params(params)?;
    let raw = argon2_key(password, salt, params)?;
    Ok(match keyfile {
        Some(kf) => Zeroizing::new(combine_keyfile(&raw, kf)),
        None => raw,
    })
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_LEN: usize = 64;
    let mut padded = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        padded[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut inner = Sha256::new();
    let mut outer = Sha256::new();
    inner.update(padded.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
    inner.update(message);
    outer.update(padded.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>());
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// HKDF-SHA256 with the Argon2id output as salt and the keyfile as input key
/// material, so the vault key needs both factors to reconstruct.
pub fn combine_keyfile(argon_key: &[u8; 32], keyfile: &[u8]) -> [u8; 32] {
    const INFO: &[u8] = b"aegis keyfile";
    let prk = hmac_sha256(argon_key, keyfile);
    hmac_sha256(&prk, &[INFO, &[1u8]].concat())
}

/// Vaults saved before the HKDF combiner used a bare SHA-256 over the
/// concatenated keys; kept so those vaults still open.
pub fn combine_keyfile_legacy(argon_key: &[u8; 32], keyfile: &[u8]) -> [u8; 32] {
    let mut combined = Zeroizing::new(Vec::with_capacity(32 + keyfile.len()));
    combined.extend_from_slice(argon_key);
    combined.extend_from_slice(keyfile);
    Sha256::digest(&*combined).into()
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::fill(&mut salt);
    salt
}

/// Encrypt `plaintext` into a complete v2 vault file.
pub fn seal(
    plaintext: &[u8],
    key: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<Vec<u8>, String> {
    // Build the header first and authenticate it as AAD, so every parameter
    // the key was derived from is bound to the ciphertext.
    let mut out = Vec::with_capacity(HEADER_LEN_V2 + plaintext.len() + 16);
    out.extend_from_slice(&MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(salt);
    out.extend_from_slice(&params.m_cost.to_le_bytes());
    out.extend_from_slice(&params.t_cost.to_le_bytes());
    out.extend_from_slice(&params.p_cost.to_le_bytes());
    let nonce_offset = out.len();
    out.resize(nonce_offset + NONCE_LEN, 0);

    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    out[nonce_offset..nonce_offset + NONCE_LEN].copy_from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &out,
            },
        )
        .map_err(|e| e.to_string())?;

    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// A successfully decrypted vault.
pub struct Opened {
    /// Decrypted payload (the vault JSON).
    pub plaintext: Zeroizing<Vec<u8>>,
    /// The key that decrypted it, keyfile already mixed in.
    pub key: Key,
    pub params: KdfParams,
    pub salt: [u8; SALT_LEN],
}

/// Salt of an existing vault file, in any supported layout.
pub fn read_salt(data: &[u8]) -> Result<[u8; SALT_LEN], String> {
    let start = if data.starts_with(&MAGIC) {
        MAGIC.len() + 1
    } else {
        0
    };
    data.get(start..start + SALT_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| "File is too short to be a valid store".to_string())
}

/// Keys to try for a vault: the current keyfile combiner first, then the
/// legacy one, since vaults from before the HKDF combiner must still open.
fn candidate_keys(raw: Key, keyfile: Option<&[u8]>) -> Vec<Key> {
    match keyfile {
        Some(kf) => vec![
            Zeroizing::new(combine_keyfile(&raw, kf)),
            Zeroizing::new(combine_keyfile_legacy(&raw, kf)),
        ],
        None => vec![raw],
    }
}

/// Decrypt a pre-v2 (headerless) payload with the given params.
pub fn try_decrypt_legacy(
    password: &str,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    params: KdfParams,
    keyfile: Option<&[u8]>,
) -> Option<(Zeroizing<Vec<u8>>, Key)> {
    let raw = derive_key(password, salt, params, None).ok()?;
    for key in candidate_keys(raw, keyfile) {
        let cipher = Aes256Gcm::new((&*key).into());
        if let Ok(plaintext) = cipher.decrypt(nonce.into(), ciphertext) {
            return Some((Zeroizing::new(plaintext), key));
        }
    }
    None
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    data.get(offset..offset + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| TRUNCATED.to_string())
}

/// Decrypt a v2 vault (must start with [`MAGIC`]).
pub fn open_v2(data: &[u8], password: &str, keyfile: Option<&[u8]>) -> Result<Opened, String> {
    if data.len() <= HEADER_LEN_V2 {
        return Err(TRUNCATED.to_string());
    }

    let version = data[MAGIC.len()];
    if version != FORMAT_VERSION {
        return Err(format!(
            "Vault version {version} is not supported by this version of Aegis"
        ));
    }

    let mut offset = MAGIC.len() + 1;
    let salt: [u8; SALT_LEN] = data[offset..offset + SALT_LEN]
        .try_into()
        .map_err(|_| TRUNCATED.to_string())?;
    offset += SALT_LEN;
    let params = KdfParams {
        m_cost: read_u32(data, offset)?,
        t_cost: read_u32(data, offset + 4)?,
        p_cost: read_u32(data, offset + 8)?,
    };
    offset += 12;
    let nonce: [u8; NONCE_LEN] = data[offset..HEADER_LEN_V2]
        .try_into()
        .map_err(|_| TRUNCATED.to_string())?;
    validate_kdf_params(params)?;
    let ciphertext = &data[HEADER_LEN_V2..];

    // Vaults saved before the header was authenticated as AAD, and before the
    // HKDF keyfile combiner, must still open: try the current forms first,
    // then fall back per candidate key.
    let raw = argon2_key(password, &salt, params)?;
    let header_aad = &data[..HEADER_LEN_V2];
    for key in candidate_keys(raw, keyfile) {
        let cipher = Aes256Gcm::new((&*key).into());
        let plaintext = cipher
            .decrypt(
                (&nonce).into(),
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad: header_aad,
                },
            )
            .or_else(|_| cipher.decrypt((&nonce).into(), ciphertext))
            .ok();
        if let Some(plaintext) = plaintext {
            return Ok(Opened {
                plaintext: Zeroizing::new(plaintext),
                key,
                params,
                salt,
            });
        }
    }

    Err(DECRYPT_ERROR.to_string())
}

fn parse_iterations_from_header(data: &[u8]) -> u32 {
    if data.len() >= SALT_LEN + ITER_LEN {
        let val = u32::from_le_bytes(
            data[SALT_LEN..SALT_LEN + ITER_LEN]
                .try_into()
                .unwrap_or([0; 4]),
        );
        if (1..=20).contains(&val) {
            return val;
        }
    }
    3
}

/// Decrypt a vault file in any supported layout.
pub fn open(data: &[u8], password: &str, keyfile: Option<&[u8]>) -> Result<Opened, String> {
    if data.len() < SALT_LEN {
        return Err("File is too short to be a valid store".to_string());
    }

    if data.starts_with(&MAGIC) {
        return open_v2(data, password, keyfile);
    }

    let salt: [u8; SALT_LEN] = data[..SALT_LEN]
        .try_into()
        .map_err(|_| "Invalid salt".to_string())?;

    let mut attempts: Vec<(usize, Vec<(u32, u32)>)> = Vec::new();
    if data.len() > HEADER_LEN_LEGACY {
        attempts.push((SALT_LEN, vec![(19456, 2), (65536, 3)]));
    }
    if data.len() > HEADER_LEN {
        let iterations = parse_iterations_from_header(data);
        attempts.push((
            SALT_LEN + ITER_LEN,
            vec![(65536, iterations), (65536, 3), (19456, 2), (65536, 2)],
        ));
    }

    for (nonce_start, param_list) in attempts {
        let nonce: [u8; NONCE_LEN] = data[nonce_start..nonce_start + NONCE_LEN]
            .try_into()
            .map_err(|_| "Invalid nonce".to_string())?;
        let ciphertext = &data[nonce_start + NONCE_LEN..];
        for (m_cost, t_cost) in param_list {
            let params = KdfParams {
                m_cost,
                t_cost,
                p_cost: 1,
            };
            if let Some((plaintext, key)) =
                try_decrypt_legacy(password, &salt, &nonce, ciphertext, params, keyfile)
            {
                return Ok(Opened {
                    plaintext,
                    key,
                    params,
                    salt,
                });
            }
        }
    }

    Err(DECRYPT_ERROR.to_string())
}
