use crate::params::*;

pub const QINV: i32 = 58728449; // q^(-1) mod 2^32

/// For finite field element a with -2^{31}Q <= a <= Q*2^31,
/// compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
///
/// Returns r.
pub fn montgomery_reduce(a: i64) -> i32 {
  let mut t = (a as i32).wrapping_mul(QINV) as i64;
  t = (a as i64 - t * Q as i64) >> 32;
  t as i32
}

/// For finite field element a with a <= 2^{31} - 2^{22} - 1,
/// compute r \equiv a (mod Q) such that -6283009 <= r <= 6283007.
//
/// Returns r.
pub fn reduce32(a: i32) -> i32 {
  let mut t = (a + (1 << 22)) >> 23;
  t = a - t * Q as i32;
  t
}

/// Add Q if input coefficient is negative.
///
/// Returns r.
pub fn caddq(a: i32) -> i32 {
  a + ((a >> 31) & Q as i32)
}
