use pqc_dilithium::*;

#[test]
fn sign_then_verify_valid() {
  let mut rng = rand::thread_rng();
  let msg = b"Hello";
  let keys = Keypair::generate(&mut rng).unwrap();
  let signature = keys.sign(msg, &mut rng).unwrap();
  assert!(verify(&signature, msg, &keys.public).is_ok())
}

#[test]
fn sign_then_verify_invalid() {
  let mut rng = rand::thread_rng();
  let msg = b"Hello";
  let keys = Keypair::generate(&mut rng).unwrap();
  let mut signature = keys.sign(msg, &mut rng).unwrap();
  signature[..4].copy_from_slice(&[255u8; 4]);
  assert!(verify(&signature, msg, &keys.public).is_err())
}
