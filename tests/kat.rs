#![cfg(all(dilithium_kat, not(feature = "random_signing")))]

use pqc_core::load::*;
use pqc_dilithium::*;
use std::path::PathBuf;

const MODE: u8 = if cfg!(feature = "mode2") {
  2
} else if cfg!(feature = "mode5") {
  5
} else {
  3
};

const AES: &str = if cfg!(feature = "aes") { "-AES" } else { "" };

#[test]
fn keypair() {
  let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  let filename = format!("PQCsignKAT_Dilithium{}{}.rsp", MODE, AES);
  let katvec = kats(&mut path.clone(), &filename);
  let bufvec = bufs(&mut path, "SeedBuffer_Dilithium");
  for (i, kat) in katvec.iter().enumerate() {
    let pk = kat.pk.clone();
    let sk = kat.sk.clone();
    let mut pk2 = [0u8; PUBLICKEYBYTES];
    let mut sk2 = [0u8; SECRETKEYBYTES];
    crypto_sign_keypair(&mut pk2, &mut sk2, Some(&bufvec[i]));
    assert_eq!(pk, pk2);
    assert_eq!(sk, sk2);
  }
}

#[test]
pub fn sign() {
  let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  let filename = format!("PQCsignKAT_Dilithium{}{}.rsp", MODE, AES);
  let katvec = kats(&mut path, &filename);
  for kat in katvec {
    let sm = kat.sm.clone();
    let msg = kat.msg.clone();
    let sk = kat.sk.clone();
    let mut sig = vec![0u8; SIGNBYTES];
    crypto_sign_signature(&mut sig, &msg, &sk);
    assert_eq!(sm[..SIGNBYTES], sig);
  }
}

#[test]
pub fn verify() {
  let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  let filename = format!("PQCsignKAT_Dilithium{}{}.rsp", MODE, AES);
  let katvec = kats(&mut path, &filename);
  for kat in katvec {
    let sm = kat.sm.clone();
    let msg = kat.msg.clone();
    let pk = kat.pk.clone();
    let res = crypto_sign_verify(&sm[..SIGNBYTES], &msg, &pk);
    assert!(res.is_ok());
  }
}
