use crate::error::DilithiumError;
use rand_core::*;

pub fn randombytes<R>(
  x: &mut [u8],
  len: usize,
  rng: &mut R,
) -> Result<(), DilithiumError>
where
  R: RngCore + CryptoRng,
{
  match rng.try_fill_bytes(&mut x[..len]) {
    Ok(_) => Ok(()),
    Err(_) => Err(DilithiumError::RandomBytesGeneration),
  }
}
