use std::fs::File;
use std::path::PathBuf;
use std::io::{prelude::*, BufReader};

use pqc_dilithium::SEEDBYTES;


/// Known Answer Tests
#[derive(Debug, Clone)]
pub struct Kat {
  pub seed: Vec<u8>,
  pub mlen: usize,
  pub msg: Vec<u8>,
  pub pk: Vec<u8>,
  pub sk: Vec<u8>,
  pub smlen: usize,
  pub sm: Vec<u8>,
}

/// Converts string octuples from tvec files into Kat structs
impl From<&[String]> for Kat {
  fn from(kat: &[String]) -> Self {
    // Extract values
    let values: Vec<String> = kat.iter()
      .map(
        |katline| {
          let val: Vec<&str> = katline.split("= ").collect();
          // Handle blank lines
          if val.len() > 1 { val[1].into() } else { val[0].into() }
        }
      ).collect();

    // Build KAT from values, ignore count at index 0
    Kat {
      seed: decode_hex(&values[1].clone()),
      mlen: values[2].parse::<usize>().unwrap(),
      msg: decode_hex(&values[3].clone()),
      pk: decode_hex(&values[4].clone()),
      sk: decode_hex(&values[5].clone()),
      smlen: values[6].parse::<usize>().unwrap(),
      sm: decode_hex(&values[7].clone()),
    }
  }
}

/// KATs path
fn kat_filepath() -> PathBuf {
  let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  path.extend(&["tests"]);
  path.extend(&["KAT"]);
  let filename = format!("PQCsignKAT_Dilithium{}{}.rsp", MODE, AES);
  path.extend(&[filename]);
  path
}

/// KATs path
fn buf_filepath() -> PathBuf {
  let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  path.extend(&["tests"]);
  path.extend(&["KAT"]);
  path.extend(&[format!("SeedBuffer_Dilithium", MODE)]);
  path
}

pub fn bufs() -> Vec<[u8; SEEDBYTES]> {
  let path = buf_filepath();
  let file = File::open(path).expect("Error loading buf file");
  let buf = BufReader::new(file);
  buf.lines()
    .map(|l| vec2array(decode_hex(&l.unwrap())))
    .collect()
}

fn parse_kats() -> Vec<String> {
  let path = kat_filepath();
  let file = File::open(path).expect("Error loading KAT file");
  let buf = BufReader::new(file);
  buf.lines()
    .map(|l| l.expect("Unable to parse line"))
    .collect()
}

/// Packs chunks of lines into Kat structs 
pub fn kats() -> Vec<Kat> {
  let lines = parse_kats();
  let kats = lines[2..].chunks_exact(9);  
  // Map String slices into Vec<KAT>
  kats.map( |c| {c.into()} ).collect::<Vec<Kat>>()
}


/// Decodes hex string into a vector of bytes
pub fn decode_hex(s: &str) -> Vec<u8> {
  (0..s.len())
    .step_by(2)
    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("Hex string decoding"))
    .collect::<Vec<u8>>()
}

pub fn vec2array(vec: Vec<u8>) -> [u8; SEEDBYTES] {
  let mut out = [0u8; SEEDBYTES];
  for i in 0..SEEDBYTES {
    out[i] = vec[i];
  }
  out
}
