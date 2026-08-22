//! ECDSA signing over secp256k1, in the compact recoverable form Graphene requires.
//!
//! # Signature format
//!
//! Hive signatures are 65 bytes: a one-byte header followed by `r || s`, each 32 bytes
//! big-endian. The header is `recovery_id + 4 + 27`, where `+4` marks a compressed
//! public key and `+27` marks the compact form — so it is always in `31..=34`.
//!
//! # Canonicality
//!
//! hived rejects a signature unless it is *canonical* in Graphene's sense: neither `r`
//! nor `s` may have its high bit set, and neither may have a zero leading byte
//! followed by a byte whose high bit is clear. Roughly one signature in 128 fails
//! this, so signing retries with a different nonce until one passes.
//!
//! The nonce comes from RFC 6979 with a 32-byte "extra entropy" field holding an
//! incrementing counter, which is what libsecp256k1 exposes as `ndata` and what beem's
//! secp256k1 backend used. Signing is therefore **deterministic**: the same key and
//! digest always produce the same signature, which makes signatures reproducible in
//! tests and comparable against beem as a regression pin.
//!
//! # Fixes relative to beem
//!
//! ### One backend, constant-time
//!
//! `beemgraphenebase.ecdsasig` selected a backend at import time in the order
//! `secp256k1prp → secp256k1 → cryptography → ecdsa`, inside a bare `except:`. With
//! none of the first three installed it fell through to `ecdsa`, a **pure-Python,
//! variable-time** scalar multiplication — the primitive behind the Minerva class of
//! attacks (GHSA-wj6h-64fc-37mp), in which signing timings leak the nonce and the
//! nonce recovers the key. Downstream projects were reduced to installing
//! `cryptography` purely to change that selection order, a security property held in
//! place by a transitive dependency with no test able to detect its loss.
//!
//! `hivecomb` binds libsecp256k1 and has exactly one code path.
//!
//! ### The nonce is not seeded from the wall clock
//!
//! beem's pure-Python branch derived `k` from
//! `sha256(digest + struct.pack("d", time.time()))`. A `double` of the current time
//! carries only a few tens of bits of real entropy and is partly predictable from
//! when the transaction was broadcast. Feeding low-entropy, attacker-estimable data
//! into nonce generation is precisely the failure mode that has repeatedly cost
//! ECDSA users their keys. Here the extra entropy is a counter, and the nonce's
//! security rests on RFC 6979's HMAC construction over the private key.
//!
//! ### Verification actually verifies
//!
//! beem's `verify_message` called `verifyPub.ecdsa_verify(message, normalSig)` and
//! **discarded the boolean result**, returning the recovered public key regardless.
//! Public-key recovery succeeds for essentially any well-formed 65-byte input, so the
//! function returned a plausible-looking key for a bogus signature and left the
//! caller to notice. Worse, `Signed_Transaction.verify()` looped `for i in range(4)`
//! and appended *every* recovery candidate that did not raise, so `pubKeysFound`
//! could hold four unrelated keys.
//!
//! [`verify`] returns `Result<PublicKey>` and errors unless the signature genuinely
//! verifies against the digest.

use crate::error::{Error, Result};
use crate::keys::{PrivateKey, PublicKey};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};
use sha2::{Digest, Sha256};
use std::fmt;

/// Length of a Graphene compact recoverable signature.
pub const SIGNATURE_LEN: usize = 65;

/// Added to the recovery id to mark a compressed key in compact form.
const HEADER_OFFSET: u8 = 4 + 27;

/// Upper bound on canonical-signature retries.
///
/// Each attempt succeeds with probability ~127/128, so exhausting this is
/// astronomically unlikely and indicates a broken backend rather than bad luck. beem
/// looped forever, logging every 20 attempts.
const MAX_CANONICAL_ATTEMPTS: u32 = 1_000;

/// A 65-byte compact recoverable signature.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Wrap 65 raw bytes, checking the header and canonicality.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_LEN {
            return Err(Error::sig(format!(
                "signature must be {SIGNATURE_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let mut buf = [0u8; SIGNATURE_LEN];
        buf.copy_from_slice(bytes);
        let sig = Signature(buf);
        sig.recovery_id()?;
        if !is_canonical(sig.rs()) {
            return Err(Error::sig("signature is not canonical"));
        }
        Ok(sig)
    }

    /// Parse a 130-character hex signature.
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.len() != SIGNATURE_LEN * 2 {
            return Err(Error::sig(format!(
                "signature hex must be {} characters, got {}",
                SIGNATURE_LEN * 2,
                s.len()
            )));
        }
        let mut buf = [0u8; SIGNATURE_LEN];
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| Error::sig("signature is not valid hex"))?;
        }
        Self::from_bytes(&buf)
    }

    /// The raw 65 bytes.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }

    /// Lowercase hex, as Hive's JSON transaction format carries it.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The 64-byte `r || s` body.
    pub fn rs(&self) -> &[u8] {
        &self.0[1..]
    }

    /// The recovery id encoded in the header byte.
    pub fn recovery_id(&self) -> Result<i32> {
        let header = self.0[0];
        if !(HEADER_OFFSET..HEADER_OFFSET + 4).contains(&header) {
            return Err(Error::sig(format!(
                "signature header byte {header} is outside the valid range {}..={}",
                HEADER_OFFSET,
                HEADER_OFFSET + 3
            )));
        }
        Ok(i32::from(header - HEADER_OFFSET))
    }

    fn to_recoverable(self) -> Result<RecoverableSignature> {
        let rec_id = RecoveryId::from_i32(self.recovery_id()?)
            .map_err(|e| Error::sig(format!("bad recovery id: {e}")))?;
        RecoverableSignature::from_compact(self.rs(), rec_id)
            .map_err(|e| Error::sig(format!("malformed compact signature: {e}")))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", self.to_hex())
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Graphene's canonicality predicate, over the 64-byte `r || s` body.
///
/// A faithful port of `beemgraphenebase.ecdsasig._is_canonical`. This one is worth
/// keeping bit-identical: it is the rule hived enforces, and any divergence produces
/// signatures the chain silently rejects.
pub fn is_canonical(rs: &[u8]) -> bool {
    if rs.len() != 64 {
        return false;
    }
    (rs[0] & 0x80) == 0
        && !(rs[0] == 0 && (rs[1] & 0x80) == 0)
        && (rs[32] & 0x80) == 0
        && !(rs[32] == 0 && (rs[33] & 0x80) == 0)
}

/// Sign a 32-byte digest, retrying until the signature is canonical.
pub fn sign_digest(digest: &[u8; 32], key: &PrivateKey) -> Result<Signature> {
    let secp = Secp256k1::signing_only();
    let msg =
        Message::from_digest_slice(digest).map_err(|e| Error::sig(format!("bad digest: {e}")))?;

    // RFC 6979 extra entropy: a big-endian counter, matching libsecp256k1's `ndata`
    // and beem's secp256k1 backend, which started at 1 and incremented.
    for counter in 1..=MAX_CANONICAL_ATTEMPTS {
        let mut nonce_data = [0u8; 32];
        nonce_data[28..].copy_from_slice(&counter.to_be_bytes());

        let rec_sig = secp.sign_ecdsa_recoverable_with_noncedata(&msg, key.inner(), &nonce_data);
        let (rec_id, compact) = rec_sig.serialize_compact();

        if !is_canonical(&compact) {
            continue;
        }

        let mut out = [0u8; SIGNATURE_LEN];
        out[0] = u8::try_from(rec_id.to_i32())
            .map_err(|_| Error::sig("recovery id out of range"))?
            + HEADER_OFFSET;
        out[1..].copy_from_slice(&compact);
        return Ok(Signature(out));
    }

    Err(Error::sig(format!(
        "no canonical signature found in {MAX_CANONICAL_ATTEMPTS} attempts"
    )))
}

/// Sign an arbitrary message: `sign_digest(sha256(message))`.
///
/// This is the primitive behind Hive's login handshakes, where the "message" is an
/// application-supplied string rather than a transaction.
pub fn sign_message(message: &[u8], key: &PrivateKey) -> Result<Signature> {
    let digest: [u8; 32] = Sha256::digest(message).into();
    sign_digest(&digest, key)
}

/// Recover the public key that produced a signature over `digest`.
///
/// # What this does and does not prove
///
/// It proves the signature is **well formed**: a malformed compact signature, or one
/// whose recovery id cannot yield a point, is an error.
///
/// It does **not** prove the signature is the one you expected. Recovery answers
/// "which key would have produced this?", and a tampered signature simply recovers a
/// *different* key. Checking the recovered key against its own signature — which is
/// what this function does internally — is therefore close to tautological, and is
/// kept only to reject inputs libsecp256k1 would otherwise accept.
///
/// **Meaningful verification requires an expected key: use [`verify`].**
///
/// This is the distinction beem's `verify_message` blurred. It performed the same
/// tautological check, discarded its result, and returned a key — leaving every caller
/// to notice that "verify_message" verifies nothing on its own.
pub fn recover(digest: &[u8; 32], signature: &Signature) -> Result<PublicKey> {
    let secp = Secp256k1::new();
    let msg =
        Message::from_digest_slice(digest).map_err(|e| Error::sig(format!("bad digest: {e}")))?;
    let rec_sig = signature.to_recoverable()?;

    let recovered = secp
        .recover_ecdsa(&msg, &rec_sig)
        .map_err(|e| Error::sig(format!("could not recover a public key: {e}")))?;

    // Recovery is not verification. Check the standard signature against the
    // recovered key before handing it back.
    secp.verify_ecdsa(&msg, &rec_sig.to_standard(), &recovered)
        .map_err(|e| Error::sig(format!("signature does not verify: {e}")))?;

    Ok(PublicKey::from_inner(recovered))
}

/// Verify a signature over `digest` against an expected public key.
///
/// This is the check that actually means something: the signature must recover to
/// exactly `expected`.
pub fn verify(digest: &[u8; 32], signature: &Signature, expected: &PublicKey) -> Result<()> {
    let recovered = recover(digest, signature)?;
    if &recovered != expected {
        return Err(Error::sig(
            "signature is valid but was made by a different key",
        ));
    }
    Ok(())
}

/// Verify a signature over an arbitrary message.
pub fn verify_message(message: &[u8], signature: &Signature, expected: &PublicKey) -> Result<()> {
    let digest: [u8; 32] = Sha256::digest(message).into();
    verify(&digest, signature, expected)
}

/// Recover the signing key from a signature over an arbitrary message.
pub fn recover_message(message: &[u8], signature: &Signature) -> Result<PublicKey> {
    let digest: [u8; 32] = Sha256::digest(message).into();
    recover(&digest, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_WIF: &str = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3";

    fn key() -> PrivateKey {
        PrivateKey::from_wif(TEST_WIF).unwrap()
    }

    #[test]
    fn signs_and_recovers() {
        let k = key();
        let sig = sign_message(b"hello hive", &k).unwrap();
        assert_eq!(sig.as_bytes().len(), 65);
        assert_eq!(
            recover_message(b"hello hive", &sig).unwrap(),
            k.public_key()
        );
        verify_message(b"hello hive", &sig, &k.public_key()).unwrap();
    }

    #[test]
    fn signatures_are_canonical() {
        let k = key();
        // Many distinct digests, so the retry loop is genuinely exercised.
        for i in 0..256u32 {
            let sig = sign_message(format!("message {i}").as_bytes(), &k).unwrap();
            assert!(
                is_canonical(sig.rs()),
                "attempt {i} produced a non-canonical signature"
            );
            let header = sig.as_bytes()[0];
            assert!((31..=34).contains(&header), "bad header byte {header}");
        }
    }

    #[test]
    fn signing_is_deterministic() {
        let k = key();
        let a = sign_message(b"repeatable", &k).unwrap();
        let b = sign_message(b"repeatable", &k).unwrap();
        assert_eq!(a, b, "RFC 6979 with a counter must be reproducible");
    }

    #[test]
    fn a_wrong_message_does_not_verify() {
        let k = key();
        let sig = sign_message(b"the real message", &k).unwrap();
        assert!(verify_message(b"a different message", &sig, &k.public_key()).is_err());
    }

    #[test]
    fn a_wrong_key_does_not_verify() {
        let k = key();
        let other = PrivateKey::generate();
        let sig = sign_message(b"msg", &k).unwrap();
        assert!(verify_message(b"msg", &sig, &other.public_key()).is_err());
    }

    #[test]
    fn tampered_signatures_are_rejected() {
        // This is the regression test for beem's discarded `ecdsa_verify` result:
        // recovery still yields *a* key for a mangled signature, so a verifier that
        // only recovers reports success.
        let k = key();
        let sig = sign_message(b"msg", &k).unwrap();
        let mut raw = *sig.as_bytes();
        raw[40] ^= 0xff;
        match Signature::from_bytes(&raw) {
            Err(_) => {}
            Ok(tampered) => {
                assert!(
                    verify_message(b"msg", &tampered, &k.public_key()).is_err(),
                    "a tampered signature must not verify"
                );
            }
        }
    }

    #[test]
    fn header_byte_is_range_checked() {
        let k = key();
        let sig = sign_message(b"msg", &k).unwrap();
        for bad_header in [0u8, 27, 30, 35, 200, 255] {
            let mut raw = *sig.as_bytes();
            raw[0] = bad_header;
            assert!(
                Signature::from_bytes(&raw).is_err(),
                "header {bad_header} should be rejected"
            );
        }
    }

    #[test]
    fn canonicality_predicate_matches_graphene() {
        let mut rs = [0x01u8; 64];
        assert!(is_canonical(&rs));

        rs[0] = 0x80; // high bit of r
        assert!(!is_canonical(&rs));

        rs = [0x01u8; 64];
        rs[32] = 0x80; // high bit of s
        assert!(!is_canonical(&rs));

        rs = [0x01u8; 64];
        rs[0] = 0x00;
        rs[1] = 0x01; // leading zero in r without a following high bit
        assert!(!is_canonical(&rs));

        rs = [0x01u8; 64];
        rs[32] = 0x00;
        rs[33] = 0x01; // same for s
        assert!(!is_canonical(&rs));

        // Wrong length is never canonical.
        assert!(!is_canonical(&[0x01u8; 63]));
    }

    #[test]
    fn hex_roundtrip() {
        let sig = sign_message(b"msg", &key()).unwrap();
        assert_eq!(Signature::from_hex(&sig.to_hex()).unwrap(), sig);
        assert!(Signature::from_hex("deadbeef").is_err());
    }
}
