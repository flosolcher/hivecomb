//! Key handling: WIF private keys, compressed public keys, and the password/brain-key
//! derivations Hive inherited from Graphene.
//!
//! # Handling of secret material
//!
//! This module holds the single most sensitive value in the crate. Three rules apply
//! to every type here, and each of them closes a hole that beem left open:
//!
//! 1. **A secret never renders.** [`PrivateKey`]'s `Debug` and `Display` print
//!    `PrivateKey(<redacted>)`. beem's `PrivateKey.__repr__` returned the raw private
//!    scalar as hex and `__str__` returned the WIF, so `print(key)`, an f-string, a
//!    `log.debug("%r", key)`, or any debugger or crash reporter that renders local
//!    variables would disclose the key. Exporting the secret in `comb` requires the
//!    explicitly-named [`PrivateKey::to_wif`] or [`PrivateKey::expose_secret`].
//! 2. **A secret is wiped.** Key bytes live in `Zeroizing` buffers and are cleared on
//!    drop. Python `str` is immutable and interned; beem could not have wiped a key
//!    even in principle.
//! 3. **A secret is never in an error.** See the note on [`crate::error::Error`].
//!
//! # Validation
//!
//! beem checked key length with a bare `assert`, which Python removes under `-O`, and
//! never checked that the scalar was a valid secp256k1 secret at all. Here a
//! [`PrivateKey`] cannot be constructed unless the scalar is in `[1, n-1]`.

mod derive;
mod private;
mod public;

pub use derive::{BrainKey, PasswordKey, Role};
pub use private::PrivateKey;
pub use public::{MaybePublicKey, PublicKey, NULL_PUBLIC_KEY};

/// Version byte prefixed to a Hive/Bitcoin mainnet WIF before base58check encoding.
pub const WIF_VERSION: u8 = 0x80;

/// Length of a compressed secp256k1 public key.
pub const COMPRESSED_PUBKEY_LEN: usize = 33;

/// Length of a secp256k1 secret scalar.
pub const SECRET_KEY_LEN: usize = 32;
