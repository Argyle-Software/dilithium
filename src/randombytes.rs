use rand_core::*;

pub fn randombytes(x: &mut [u8], len: usize) {
  let _ = match OsRng.try_fill_bytes(&mut x[..len]) {
    Ok(_) => Ok(()),
    Err(_) => Err(()),
};
}
