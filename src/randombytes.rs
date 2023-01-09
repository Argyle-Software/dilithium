#[cfg(not(test))]
use rand::prelude::*;

#[cfg(not(test))]
pub fn randombytes(x: &mut [u8], len: usize)
{
  thread_rng().fill_bytes(&mut x[..len])
}

#[cfg(test)]
pub fn randombytes(_x: &mut [u8], _len: usize)
{
  ()
}
