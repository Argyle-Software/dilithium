#[cfg(feature = "aes")]
mod aes256ctr;
mod api;
mod fips202;
mod ntt;
mod poly;
mod polyvec;
mod randombytes;
mod reduce;
mod rounding;
mod sign;
mod symmetric;
#[cfg(feature = "aes")]
mod symmetric_aes;
#[cfg(not(feature = "aes"))]
mod symmetric_shake;
mod packing;

mod params;
pub use params::*;

pub use api::*;

#[cfg(dilithium_kat)]
pub use sign::{
  crypto_sign_keypair, 
  crypto_sign_signature, 
  crypto_sign_verify
};