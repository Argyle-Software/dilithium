use rand_core::*;
use rand_core::OsRng;

pub fn randombytes(x: &mut [u8], len: usize) {
  //thread_rng().fill_bytes(&mut x[..len])
  let _ = match OsRng.try_fill_bytes(&mut x[..len]) {
    Ok(_) => Ok(()),
    Err(_) => Err(()),
};
}
