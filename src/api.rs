use std::convert::TryInto;

use crate::params::{PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};
use crate::sign::*;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Keypair {
  pub public: [u8; PUBLICKEYBYTES],
  secret: [u8; SECRETKEYBYTES],
}

/// Secret key elided
impl std::fmt::Debug for Keypair {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "public: {:?}\nsecret: <elided>", self.public)
  }
}

pub enum SignError {
  Input,
  ConversionFailed,
  Verify,
}

impl Keypair {
  /// Constructs a new `Keypair` from public and secret key bytes.
  ///
  /// # Errors
  /// Returns `SignError::ConversionFailed` if the byte vectors are not of the expected length.
  ///
  /// # Example
  /// ```
  /// # use pqc_dilithium::*;
  /// # use crate::params::{PUBLICKEYBYTES, SECRETKEYBYTES};
  /// let public = vec![0u8; PUBLICKEYBYTES];
  /// let secret = vec![0u8; SECRETKEYBYTES];
  /// let keypair = Keypair::new(public, secret);
  /// assert!(keypair.is_ok());
  /// ```
  pub fn new(
    pub_bytes: Vec<u8>,
    sec_bytes: Vec<u8>,
  ) -> Result<Self, SignError> {
    let public = pub_bytes
      .try_into()
      .map_err(|_| SignError::ConversionFailed)?;
    let secret = sec_bytes
      .try_into()
      .map_err(|_| SignError::ConversionFailed)?;
    Ok(Self { public, secret })
  }

  /// Explicitly expose secret key
  /// ```
  /// # use pqc_dilithium::*;
  /// let keys = Keypair::generate();
  /// let secret_key = keys.expose_secret();
  /// assert!(secret_key.len() == SECRETKEYBYTES);
  /// ```
  pub fn expose_secret(&self) -> &[u8] {
    &self.secret
  }

  /// Generates a keypair for signing and verification
  ///
  /// Example:
  /// ```
  /// # use pqc_dilithium::*;
  /// let keys = Keypair::generate();
  /// assert!(keys.public.len() == PUBLICKEYBYTES);
  /// assert!(keys.expose_secret().len() == SECRETKEYBYTES);
  /// ```
  pub fn generate() -> Keypair {
    let mut public = [0u8; PUBLICKEYBYTES];
    let mut secret = [0u8; SECRETKEYBYTES];
    crypto_sign_keypair(&mut public, &mut secret, None);
    Keypair { public, secret }
  }

  /// Generates a signature for the given message using a keypair
  ///
  /// Example:
  /// ```
  /// # use pqc_dilithium::*;
  /// # let keys = Keypair::generate();
  /// let msg = "Hello".as_bytes();
  /// let sig = keys.sign(&msg);
  /// assert!(sig.len() == SIGNBYTES);
  /// ```  
  pub fn sign(&self, msg: &[u8]) -> [u8; SIGNBYTES] {
    let mut sig = [0u8; SIGNBYTES];
    crypto_sign_signature(&mut sig, msg, &self.secret);
    sig
  }
}

/// Verify signature using keypair
///
/// Example:
/// ```
/// # use pqc_dilithium::*;
/// # let keys = Keypair::generate();
/// # let msg = [0u8; 32];
/// # let sig = keys.sign(&msg);
/// let sig_verify = verify(&sig, &msg, &keys.public);
/// assert!(sig_verify.is_ok());
pub fn verify(
  sig: &[u8],
  msg: &[u8],
  public_key: &[u8],
) -> Result<(), SignError> {
  if sig.len() != SIGNBYTES {
    return Err(SignError::Input);
  }
  crypto_sign_verify(&sig, &msg, public_key)
}
