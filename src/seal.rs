//! Authenticated encryption of the serialized server login state.
//!
//! The raw `ServerLogin` state holds the session key and the MAC key that verifies the client's
//! finish message, so whoever sees it can finish the login without the password. Sealing it with a
//! key only the server knows makes it safe to park in a cache, cookie or log, keeps the server
//! stateless, and bounds replay with an expiry that is authenticated together with the state.
//!
//! Layout: `version(1) || nonce(24) || XChaCha20-Poly1305(expiry_be(8) || state)`, with the version
//! byte as associated data. The key is HKDF-SHA512 of the server setup, so there is no extra secret
//! to configure and rotating the setup invalidates in-flight logins (seconds of exposure) only.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use opaque_ke::rand::{rngs::OsRng, RngCore};
use sha2::Sha512;
use zeroize::Zeroizing;

const VERSION: u8 = 1;
const KDF_INFO: &[u8] = b"cyphra-opaque/login-state/v1";
const NONCE_LEN: usize = 24;
const EXPIRY_LEN: usize = 8;
// ponytail: fixed window; it must cover client-side Argon2 plus the network round trip. Make it a
// parameter if a deployment needs longer.
pub const STATE_TTL_SECS: u64 = 120;

#[derive(Debug)]
pub struct SealError;

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cipher(setup: &[u8]) -> Result<XChaCha20Poly1305, SealError> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha512>::new(None, setup)
        .expand(KDF_INFO, &mut *key)
        .map_err(|_| SealError)?;
    Ok(XChaCha20Poly1305::new(key.as_slice().into()))
}

pub fn seal(setup: &[u8], state: &[u8], now: u64) -> Result<Vec<u8>, SealError> {
    let mut plaintext = Zeroizing::new(Vec::with_capacity(EXPIRY_LEN + state.len()));
    plaintext.extend_from_slice(&now.saturating_add(STATE_TTL_SECS).to_be_bytes());
    plaintext.extend_from_slice(state);

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher(setup)?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &[VERSION],
            },
        )
        .map_err(|_| SealError)?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Returns the raw state only if the blob is authentic, was sealed under this setup and has not
/// expired. Every failure is the same error so callers cannot tell the causes apart.
pub fn open(setup: &[u8], sealed: &[u8], now: u64) -> Result<Zeroizing<Vec<u8>>, SealError> {
    if sealed.len() <= 1 + NONCE_LEN || sealed[0] != VERSION {
        return Err(SealError);
    }
    let (nonce, ciphertext) = sealed[1..].split_at(NONCE_LEN);
    let plaintext = Zeroizing::new(
        cipher(setup)?
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &[VERSION],
                },
            )
            .map_err(|_| SealError)?,
    );
    if plaintext.len() <= EXPIRY_LEN {
        return Err(SealError);
    }
    let (expiry, state) = plaintext.split_at(EXPIRY_LEN);
    let mut buf = [0u8; EXPIRY_LEN];
    buf.copy_from_slice(expiry);
    let expiry = u64::from_be_bytes(buf);
    if now > expiry {
        return Err(SealError);
    }
    Ok(Zeroizing::new(state.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SETUP: &[u8] = b"setup-a";
    const STATE: &[u8] = &[7u8; 192];

    #[test]
    fn round_trips_and_hides_the_state() {
        let sealed = seal(SETUP, STATE, 1_000).unwrap();
        assert!(!sealed.windows(32).any(|w| w == &STATE[..32]));
        assert_eq!(&*open(SETUP, &sealed, 1_000).unwrap(), STATE);
        assert_ne!(
            sealed,
            seal(SETUP, STATE, 1_000).unwrap(),
            "fresh nonce per seal"
        );
    }

    #[test]
    fn rejects_expired_foreign_and_malformed_blobs() {
        let sealed = seal(SETUP, STATE, 1_000).unwrap();
        assert!(open(SETUP, &sealed, 1_000 + STATE_TTL_SECS).is_ok());
        assert!(open(SETUP, &sealed, 1_000 + STATE_TTL_SECS + 1).is_err());
        assert!(open(b"setup-b", &sealed, 1_000).is_err());
        assert!(open(SETUP, &[], 1_000).is_err());
        assert!(open(SETUP, &sealed[..1 + NONCE_LEN], 1_000).is_err());
        let mut wrong_version = sealed.clone();
        wrong_version[0] = 2;
        assert!(open(SETUP, &wrong_version, 1_000).is_err());
    }

    #[test]
    fn any_flipped_bit_is_rejected() {
        let sealed = seal(SETUP, STATE, 1_000).unwrap();
        for i in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[i] ^= 1;
            assert!(open(SETUP, &tampered, 1_000).is_err(), "byte {}", i);
        }
    }
}
