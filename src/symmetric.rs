use crate::fips202::*;
use crate::params::{CRHBYTES, SEEDBYTES};

#[cfg(feature = "aes")]
use crate::aes256ctr::*;

#[cfg(not(feature = "aes"))]
pub type Stream128State = KeccakState;
#[cfg(feature = "aes")]
pub type Stream128State = Aes256ctrCtx;
#[cfg(not(feature = "aes"))]
pub type Stream256State = KeccakState;
#[cfg(feature = "aes")]
pub type Stream256State = Aes256ctrCtx;

#[cfg(feature = "aes")]
pub const STREAM128_BLOCKBYTES: usize = AES256CTR_BLOCKBYTES;
#[cfg(not(feature = "aes"))]
pub const STREAM128_BLOCKBYTES: usize = SHAKE128_RATE;

#[cfg(feature = "aes")]
pub const STREAM256_BLOCKBYTES: usize = AES256CTR_BLOCKBYTES;
#[cfg(not(feature = "aes"))]
pub const STREAM256_BLOCKBYTES: usize = SHAKE256_RATE;

pub fn _crh(out: &mut [u8], input: &[u8], inbytes: usize) {
  shake256(out, CRHBYTES, input, inbytes)
}

pub fn stream128_init(state: &mut Stream128State, seed: &[u8], nonce: u16) {
  #[cfg(not(feature = "aes"))]
  dilithium_shake128_stream_init(state, seed, nonce);

  #[cfg(feature = "aes")]
  dilithium_aes256ctr_init(state, seed, nonce)
}

pub fn stream128_squeezeblocks(
  out: &mut [u8],
  outblocks: u64,
  state: &mut Stream128State,
) {
  #[cfg(not(feature = "aes"))]
  shake128_squeezeblocks(out, outblocks as usize, state);

  #[cfg(feature = "aes")]
  aes256ctr_squeezeblocks(out, outblocks, state);
}

pub fn stream256_init(state: &mut Stream256State, seed: &[u8], nonce: u16) {
  #[cfg(not(feature = "aes"))]
  dilithium_shake256_stream_init(state, seed, nonce);

  #[cfg(feature = "aes")]
  dilithium_aes256ctr_init(state, seed, nonce)
}

pub fn stream256_squeezeblocks(
  out: &mut [u8],
  outblocks: u64,
  state: &mut Stream256State,
) {
  #[cfg(not(feature = "aes"))]
  shake256_squeezeblocks(out, outblocks as usize, state);

  #[cfg(feature = "aes")]
  aes256ctr_squeezeblocks(out, outblocks, state);
}

#[cfg(feature = "aes")]
pub fn dilithium_aes256ctr_init(
  state: &mut Aes256ctrCtx,
  key: &[u8],
  nonce: u16,
) {
  let mut expnonce = [0u8; 12];
  expnonce[0] = nonce as u8;
  expnonce[1] = (nonce >> 8) as u8;
  aes256ctr_init(state, key, expnonce);
}

#[cfg(not(feature = "aes"))]
pub fn dilithium_shake128_stream_init(
  state: &mut KeccakState,
  seed: &[u8],
  nonce: u16,
) {
  let t = [nonce as u8, (nonce >> 8) as u8];
  state.init();
  shake128_absorb(state, seed, SEEDBYTES);
  shake128_absorb(state, &t, 2);
  shake128_finalize(state);
}

#[cfg(not(feature = "aes"))]
pub fn dilithium_shake256_stream_init(
  state: &mut KeccakState,
  seed: &[u8],
  nonce: u16,
) {
  let t = [nonce as u8, (nonce >> 8) as u8];
  state.init();
  shake256_absorb(state, seed, CRHBYTES);
  shake256_absorb(state, &t, 2);
  shake256_finalize(state);
}
