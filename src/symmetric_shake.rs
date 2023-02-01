use crate::{fips202::*, params::*};

pub fn dilithium_shake128_stream_init(
  state: &mut KeccakState,
  seed: &[u8],
  nonce: u16,
)
{
  let t = [nonce as u8, (nonce >> 8) as u8];
  state.init();
  shake128_absorb(state, seed, SEEDBYTES);
  shake128_absorb(state, &t, 2);
  shake128_finalize(state);
}

pub fn dilithium_shake256_stream_init(
  state: &mut KeccakState,
  seed: &[u8],
  nonce: u16,
)
{
  let t = [nonce as u8, (nonce >> 8) as u8];
  state.init();
  shake256_absorb(state, seed, CRHBYTES);
  shake256_absorb(state, &t, 2);
  shake256_finalize(state);
}
