//! The one place this crate draws randomness from.
//!
//! `rand` 0.9 made `OsRng` **fallible**, and that is the honest shape: `getrandom` can
//! fail — an exhausted file descriptor table, a seccomp filter, a kernel too old for
//! `getrandom(2)` with `/dev/urandom` unavailable. Under `rand` 0.8 the same failure
//! panicked inside the library.
//!
//! Every caller here already returns `Result`, so the failure propagates instead. That
//! matters more in this crate than in most: a key or a nonce drawn from a failed source
//! is not a degraded outcome, it is a catastrophic one, and the caller should be the one
//! deciding what to do about it.
//!
//! `OsRng` rather than a userspace CSPRNG, everywhere, for the reason given on
//! [`crate::PrivateKey::generate`]: one source for every secret this crate creates.

use crate::error::{Error, Result};

/// Fill `buf` from the operating system CSPRNG.
pub(crate) fn fill(buf: &mut [u8]) -> Result<()> {
    use rand::TryRngCore;
    rand::rngs::OsRng
        .try_fill_bytes(buf)
        .map_err(|e| Error::key(format!("the operating system CSPRNG failed: {e}")))
}

/// A single `u32` from the operating system CSPRNG.
pub(crate) fn next_u32() -> Result<u32> {
    use rand::TryRngCore;
    rand::rngs::OsRng
        .try_next_u32()
        .map_err(|e| Error::key(format!("the operating system CSPRNG failed: {e}")))
}
