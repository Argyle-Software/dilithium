use pqc_dilithium::*;

#[test]
fn sign_then_verify_valid()
{
  let msg = b"Hello";
  let keys = Keypair::generate();
  let signature = keys.sign(msg);
  assert!(verify(&signature, msg, &keys.public).is_ok())
}

#[test]
fn sign_then_verify_invalid()
{
  let msg = b"Hello";
  let keys = Keypair::generate();
  let mut signature = keys.sign(msg);
  signature[..4].copy_from_slice(&[255u8; 4]);
  assert!(verify(&signature, msg, &keys.public).is_err())
}
