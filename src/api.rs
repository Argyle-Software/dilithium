// use signature::Signature;

use crate::params::{CRYPTO_SECRETKEYBYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_BYTES};
use crate::sign::*;


#[derive(Copy, Clone)]
pub struct Keypair {
  pub public: [u8; CRYPTO_PUBLICKEYBYTES],
  secret: [u8; CRYPTO_SECRETKEYBYTES]
}

impl Keypair {
  /// Explicitly expose secret key
  pub fn expose_secret(&self) -> &[u8] {
    &self.secret
  }
}

/// Secret key elided
impl std::fmt::Debug for Keypair {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {  
    write!(f, "public: {:?}\nsecret: <elided>", self.public)
  }
}

pub enum SigError {
  Input,
  Verify
}

/// Generates a keypair for signing and verification
/// 
/// Example: 
/// ```no_run
/// # use pqc_dilithium::*;
/// let keys = keypair();
/// assert!(keys.public.len() == CRYPTO_PUBLICKEYBYTES);
/// assert!(keys.expose_secret().len() == CRYPTO_SECRETKEYBYTES);
/// ```
pub fn keypair() -> Keypair
{
  let mut public = [0u8; CRYPTO_PUBLICKEYBYTES];
  let mut secret = [0u8; CRYPTO_SECRETKEYBYTES];
  crypto_sign_keypair(&mut public, &mut secret, None);
  Keypair { public, secret }
}

/// Generates a signature for the given message using a keypair
/// 
/// Example: 
/// ```no_run
/// # use pqc_dilithium::*;
/// # let keys = keypair();
/// let msg = "Hello".as_bytes();
/// let sig = sign(&msg, &keys);
/// assert!(sig.len() == CRYPTO_BYTES);
/// ```  
pub fn sign(msg: &[u8], keypair: &Keypair) -> [u8; CRYPTO_BYTES] 
{
  let mut sig = [0u8; CRYPTO_BYTES];
  crypto_sign_signature(&mut sig, msg, &keypair.secret);
  sig
}

/// Verify signature using keypair
/// 
/// Example: 
/// ```no_run
/// # use pqc_dilithium::*;
/// # let keys = keypair();
/// # let msg = [0u8; 32];
/// # let sig = sign(&msg, &keys);
/// let sig_verify = verify(&sig, &msg, &keys);
/// assert!(sig_verify.is_ok());
pub fn verify(sig: &[u8], msg: &[u8], keypair: &Keypair) -> Result<(), SigError>
{
  if sig.len() != CRYPTO_BYTES {
    return Err(SigError::Input)
  }
  crypto_sign_verify(&sig, &msg, &keypair.public)
}