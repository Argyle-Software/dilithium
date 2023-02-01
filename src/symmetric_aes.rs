use crate::aes256ctr::*;

pub fn dilithium_aes256ctr_init(
  state: &mut Aes256ctrCtx,
  key: &[u8],
  nonce: u16,
)
{
  let mut expnonce = [0u8; 12];
  expnonce[0] = nonce as u8;
  expnonce[1] = (nonce >> 8) as u8;
  aes256ctr_init(state, key, expnonce);
}
