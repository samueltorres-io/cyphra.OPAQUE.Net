use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use opaque_ke::rand::{rngs::OsRng, RngCore};
use sha2::Sha512;
use zeroize::Zeroizing;

const VERSION: u8 = 2;
const KDF_INFO: &[u8] = b"cyphra-opaque/login-state/v1";
const NONCE_LEN: usize = 24;
const EXPIRY_LEN: usize = 8;
pub const STATE_TTL_SECS: u64 = 120;
const MAX_CLOCK_SKEW_SECS: u64 = 30;

#[derive(Debug)]
pub struct SealError;

pub fn unix_now() -> Result<u64, SealError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| SealError)
}

fn cipher(setup: &[u8]) -> Result<XChaCha20Poly1305, SealError> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha512>::new(None, setup)
        .expand(KDF_INFO, &mut *key)
        .map_err(|_| SealError)?;
    XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| SealError)
}

fn associated_data(user: &[u8]) -> Vec<u8> {
    [&[VERSION][..], user].concat()
}

pub fn seal(setup: &[u8], user: &[u8], state: &[u8], now: u64) -> Result<Vec<u8>, SealError> {
    let mut plaintext = Zeroizing::new(Vec::with_capacity(EXPIRY_LEN + state.len()));
    plaintext.extend_from_slice(&now.saturating_add(STATE_TTL_SECS).to_be_bytes());
    plaintext.extend_from_slice(state);

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher(setup)?
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: &associated_data(user),
            },
        )
        .map_err(|_| SealError)?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open(
    setup: &[u8],
    user: &[u8],
    sealed: &[u8],
    now: u64,
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    if sealed.len() <= 1 + NONCE_LEN || sealed[0] != VERSION {
        return Err(SealError);
    }
    let (nonce, ciphertext) = sealed[1..].split_at(NONCE_LEN);
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(nonce);
    let nonce = XNonce::from(n);
    let plaintext = Zeroizing::new(
        cipher(setup)?
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &associated_data(user),
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
    if now > expiry || expiry - now > STATE_TTL_SECS + MAX_CLOCK_SKEW_SECS {
        return Err(SealError);
    }
    Ok(Zeroizing::new(state.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SETUP: &[u8] = b"setup-a";
    const STATE: &[u8] = &[7u8; 192];
    const USER: &[u8] = b"alice";

    #[test]
    fn round_trips_and_hides_the_state() {
        let sealed = seal(SETUP, USER, STATE, 1_000).unwrap();
        assert!(!sealed.windows(32).any(|w| w == &STATE[..32]));
        assert_eq!(&*open(SETUP, USER, &sealed, 1_000).unwrap(), STATE);
        assert_ne!(
            sealed,
            seal(SETUP, USER, STATE, 1_000).unwrap(),
            "fresh nonce per seal"
        );
    }

    #[test]
    fn rejects_expired_foreign_and_malformed_blobs() {
        let sealed = seal(SETUP, USER, STATE, 1_000).unwrap();
        assert!(open(SETUP, USER, &sealed, 1_000 + STATE_TTL_SECS).is_ok());
        assert!(open(SETUP, USER, &sealed, 1_000 + STATE_TTL_SECS + 1).is_err());
        assert!(open(b"setup-b", USER, &sealed, 1_000).is_err());
        assert!(open(SETUP, USER, &[], 1_000).is_err());
        assert!(open(SETUP, USER, &sealed[..1 + NONCE_LEN], 1_000).is_err());
        let mut wrong_version = sealed.clone();
        wrong_version[0] = 1;
        assert!(open(SETUP, USER, &wrong_version, 1_000).is_err());
    }

    #[test]
    fn opens_only_for_the_user_it_was_sealed_for() {
        let sealed = seal(SETUP, USER, STATE, 1_000).unwrap();
        assert!(open(SETUP, b"bob", &sealed, 1_000).is_err());
        assert!(open(SETUP, b"", &sealed, 1_000).is_err());
        assert!(open(SETUP, b"alice ", &sealed, 1_000).is_err());
        assert!(open(SETUP, USER, &sealed, 1_000).is_ok());
    }

    #[test]
    fn rejects_a_state_sealed_by_a_clock_too_far_ahead() {
        let sealed = seal(SETUP, USER, STATE, 1_000).unwrap();
        assert!(open(SETUP, USER, &sealed, 1_000 - MAX_CLOCK_SKEW_SECS).is_ok());
        assert!(open(SETUP, USER, &sealed, 1_000 - MAX_CLOCK_SKEW_SECS - 1).is_err());
    }

    #[test]
    fn any_flipped_bit_is_rejected() {
        let sealed = seal(SETUP, USER, STATE, 1_000).unwrap();
        for i in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[i] ^= 1;
            assert!(open(SETUP, USER, &tampered, 1_000).is_err(), "byte {}", i);
        }
    }
}
