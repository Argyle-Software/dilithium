#![allow(non_snake_case)]
extern crate alloc;

use super::*;
use crate::params::{PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};
use alloc::boxed::Box;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Keys {
  keypair: api::Keypair,
}

#[wasm_bindgen]
pub fn keypair() -> Result<Keys, JsError> {
  let mut rng = rand::rngs::OsRng {};
  match api::Keypair::generate(&mut rng) {
    Ok(keypair) => Ok(Keys { keypair }),
    Err(error::DilithiumError::RandomBytesGeneration) => {
      Err(JsError::new("Error trying to fill random bytes"))
    }
    _ => Err(JsError::new("The keypair could not be generated")),
  }
}

#[wasm_bindgen]
impl Keys {
  #[wasm_bindgen(constructor)]
  pub fn new() -> Result<Keys, JsError> {
    keypair()
  }

  #[wasm_bindgen(getter)]
  pub fn pubkey(&self) -> Box<[u8]> {
    Box::new(self.keypair.public)
  }

  #[wasm_bindgen(getter)]
  pub fn secret(&self) -> Box<[u8]> {
    self.keypair.expose_secret().to_vec().into_boxed_slice()
  }

  #[wasm_bindgen]
  pub fn sign(&self, msg: Box<[u8]>) -> Result<Box<[u8]>, JsValue> {
    let mut rng = rand::rngs::OsRng {};
    match self.keypair.sign(&msg, &mut rng) {
      Ok(signature) => Ok(Box::new(signature)),
      Err(_) => Err(JsValue::null()),
    }
  }
}

#[wasm_bindgen]
pub fn verify(sig: Box<[u8]>, msg: Box<[u8]>, public_key: Box<[u8]>) -> bool {
  api::verify(&sig, &msg, &public_key).is_ok()
}

#[wasm_bindgen]
pub struct Params {
  #[wasm_bindgen(readonly)]
  pub publicKeyBytes: usize,
  #[wasm_bindgen(readonly)]
  pub secretKeyBytes: usize,
  #[wasm_bindgen(readonly)]
  pub signBytes: usize,
}

#[wasm_bindgen]
impl Params {
  #[wasm_bindgen(getter)]
  pub fn publicKeyBytes() -> usize {
    PUBLICKEYBYTES
  }

  #[wasm_bindgen(getter)]
  pub fn secretKeyBytes() -> usize {
    SECRETKEYBYTES
  }

  #[wasm_bindgen(getter)]
  pub fn signBytes() -> usize {
    SIGNBYTES
  }
}
