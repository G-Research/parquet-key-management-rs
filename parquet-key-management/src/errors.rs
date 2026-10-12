//! Error types used by this crate

use std::error::Error as StdError;
use std::fmt;

/// Errors that can occur when managing Parquet encryption keys
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A general error with a message
    General(String),
    /// Functionality that is not yet implemented
    NotYetImplemented(String),
    /// An error originating from an external source, such as a KMS client library
    External(Box<dyn StdError + Send + Sync>),
}

/// A specialized `Result` type for key management operations
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::General(message) => write!(f, "Key management error: {message}"),
            Error::NotYetImplemented(message) => write!(f, "Not yet implemented: {message}"),
            Error::External(e) => write!(f, "External error: {e}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::External(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<ring::error::Unspecified> for Error {
    fn from(e: ring::error::Unspecified) -> Self {
        Error::External(Box::new(e))
    }
}

#[cfg(feature = "parquet")]
impl From<Error> for parquet::errors::ParquetError {
    fn from(e: Error) -> Self {
        match e {
            Error::General(message) => parquet::errors::ParquetError::General(message),
            Error::NotYetImplemented(message) => parquet::errors::ParquetError::NYI(message),
            Error::External(e) => parquet::errors::ParquetError::External(e),
        }
    }
}

#[cfg(feature = "parquet")]
impl From<parquet::errors::ParquetError> for Error {
    fn from(e: parquet::errors::ParquetError) -> Self {
        Error::External(Box::new(e))
    }
}

#[cfg(feature = "datafusion")]
impl From<Error> for datafusion_common::DataFusionError {
    fn from(e: Error) -> Self {
        datafusion_common::DataFusionError::ParquetError(Box::new(e.into()))
    }
}
