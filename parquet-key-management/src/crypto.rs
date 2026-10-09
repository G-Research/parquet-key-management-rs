//! Selects the cryptography backend used by this crate.
//!
//! aws-lc-rs provides a ring-compatible API, so the rest of the crate uses these
//! re-exports rather than referring to either crate directly.
//! If both the `ring` and `aws-lc-rs` features are enabled, aws-lc-rs takes precedence.

#[cfg(feature = "aws-lc-rs")]
pub(crate) use aws_lc_rs::{aead, rand};

#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
pub(crate) use ring::{aead, rand};

#[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
compile_error!("One of the `ring` or `aws-lc-rs` features must be enabled");
