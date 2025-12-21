
//! X25519 + HKDF backup protection.

use crate::memory::GuardedKey32;
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

pub fn csrng(out: &mut GuardedKey32) -> Result<(), CsrngError> {
    OsRng.try_fill_bytes(out.borrow_mut())
        .map_err(|_| CsrngError::Failed)?;
    Ok(())
}

pub fn encapsulate(
    peer_pub: &[u8; 32],
    ctx: &[u8],
) -> Result<(Encapsulation, GuardedKey32), KEMError> {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let pubkey = PublicKey::from(&secret);

    let peer = PublicKey::from(*peer_pub);
    let shared = secret.diffie_hellman(&peer);

    let mut out = GuardedKey32::zeroed();
    let hk = Hkdf::<Sha256>::new(Some(ctx), shared.as_bytes());
    hk.expand(b"rcxcloud-backup", out.borrow_mut())
        .map_err(|_| KEMError::Derive)?;

    Ok((Encapsulation { ephemeral_public: pubkey.to_bytes() }, out))
}

pub fn decapsulate(
    our_secret: &StaticSecret,
    peer_ephemeral: &[u8; 32],
    ctx: &[u8],
    out: &mut GuardedKey32,
) -> Result<(), KEMError> {
    let peer = PublicKey::from(*peer_ephemeral);
    let shared = our_secret.diffie_hellman(&peer);

    let hk = Hkdf::<Sha256>::new(Some(ctx), shared.as_bytes());
    hk.expand(b"rcxcloud-backup", out.borrow_mut())
        .map_err(|_| KEMError::Derive)?;

    Ok(())
}

pub struct Encapsulation {
    pub ephemeral_public: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsrngError {
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KEMError {
    Derive,
}
