//! WebAuthn credential primitives: ES256 (P-256) key generation and signing.
//! Everything the browser needs to assemble (authenticator data, CBOR, client
//! data) is built in the extension; only key material lives here.

use crate::models::{Passkey, now_unix};
use aes_gcm::aead::OsRng;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use rand::Rng;
use zeroize::Zeroizing;

pub fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64_decode(text: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('='))
        .map_err(|_| "invalid base64url".to_string())
}

/// Public half of a new credential, as the extension needs it.
pub struct NewCredential {
    pub passkey: Passkey,
    pub x: String,
    pub y: String,
}

pub struct UserInfo<'a> {
    pub handle: &'a str,
    pub name: &'a str,
    pub display_name: &'a str,
}

pub fn create(rp_id: &str, user: UserInfo<'_>) -> NewCredential {
    let signing_key = SigningKey::random(&mut OsRng);
    let point = signing_key.verifying_key().to_encoded_point(false);
    let (x, y) = match (point.x(), point.y()) {
        (Some(x), Some(y)) => (b64_encode(x), b64_encode(y)),
        _ => unreachable!("an uncompressed P-256 point always has both coordinates"),
    };

    let mut credential_id = [0u8; 32];
    rand::rng().fill_bytes(&mut credential_id);
    let private_key = Zeroizing::new(b64_encode(signing_key.to_bytes().as_slice()));

    NewCredential {
        passkey: Passkey {
            credential_id: b64_encode(&credential_id),
            rp_id: rp_id.to_ascii_lowercase(),
            user_handle: user.handle.to_string(),
            user_name: user.name.to_string(),
            user_display_name: user.display_name.to_string(),
            private_key,
            created_at: now_unix(),
        },
        x,
        y,
    }
}

/// ECDSA-SHA256 signature over `data`, DER encoded as WebAuthn requires.
pub fn sign(passkey: &Passkey, data: &[u8]) -> Result<Vec<u8>, String> {
    let secret = Zeroizing::new(b64_decode(&passkey.private_key)?);
    let signing_key = SigningKey::from_slice(&secret)
        .map_err(|_| "stored passkey has an invalid private key".to_string())?;
    let signature: Signature = signing_key.sign(data);
    Ok(signature.to_der().as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::EncodedPoint;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;

    fn user() -> UserInfo<'static> {
        UserInfo {
            handle: "dXNlci0x",
            name: "alice",
            display_name: "Alice",
        }
    }

    #[test]
    fn created_credentials_are_unique_and_lowercased() {
        let a = create("Example.COM", user());
        let b = create("example.com", user());
        assert_eq!(a.passkey.rp_id, "example.com");
        assert_ne!(a.passkey.credential_id, b.passkey.credential_id);
        assert_ne!(*a.passkey.private_key, *b.passkey.private_key);
        assert_eq!(b64_decode(&a.passkey.credential_id).unwrap().len(), 32);
    }

    #[test]
    fn signature_verifies_against_the_published_public_key() {
        let credential = create("example.com", user());
        let data = b"authenticator data || client data hash";
        let der = sign(&credential.passkey, data).unwrap();

        let point = EncodedPoint::from_affine_coordinates(
            b64_decode(&credential.x).unwrap().as_slice().into(),
            b64_decode(&credential.y).unwrap().as_slice().into(),
            false,
        );
        let verifying_key = VerifyingKey::from_encoded_point(&point).unwrap();
        let signature = Signature::from_der(&der).unwrap();
        verifying_key.verify(data, &signature).unwrap();
        assert!(verifying_key.verify(b"other data", &signature).is_err());
    }

    #[test]
    fn rejects_corrupt_private_keys() {
        let mut credential = create("example.com", user());
        credential.passkey.private_key = Zeroizing::new("AAAA".to_string());
        assert!(sign(&credential.passkey, b"x").is_err());
        credential.passkey.private_key = Zeroizing::new("!!!".to_string());
        assert!(sign(&credential.passkey, b"x").is_err());
    }

    #[test]
    fn base64url_round_trips_without_padding() {
        let bytes = [0xfb, 0xff, 0xfe, 0x01];
        let text = b64_encode(&bytes);
        assert!(!text.contains(['+', '/', '=']));
        assert_eq!(b64_decode(&text).unwrap(), bytes);
        assert_eq!(b64_decode(&format!("{text}==")).unwrap(), bytes);
    }
}
