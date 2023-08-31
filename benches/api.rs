use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pqc_dilithium::*;

fn sign_small_msg(c: &mut Criterion) {
  let keys = Keypair::generate();
  let msg = "Hello".as_bytes();
  c.bench_function("Sign Small Message", |b| {
    b.iter(|| keys.sign(black_box(msg)))
  });
}

fn verify_small_msg(c: &mut Criterion) {
  let keys = Keypair::generate();
  let msg = "Hello".as_bytes();
  let sig = keys.sign(msg);
  c.bench_function("Verify Small Message", |b| {
    b.iter(|| verify(black_box(sig), black_box(msg), black_box(&keys.public)))
  });
}

criterion_group!(benches, sign_small_msg, verify_small_msg);
criterion_main!(benches);
