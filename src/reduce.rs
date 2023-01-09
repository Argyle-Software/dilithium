use crate::params::*;

pub const QINV: i32 =  58728449; // q^(-1) mod 2^32

/*************************************************
* Name:        montgomery_reduce
*
* Description: For finite field element a with -2^{31}Q <= a <= Q*2^31,
*              compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
*
* Arguments:   - int64_t: finite field element a
*
* Returns r.
**************************************************/
pub fn montgomery_reduce(a: i64) -> i32 {
  let mut t = (a as i32).wrapping_mul(QINV) as i64;
  t = (a as i64 - t * Q as i64) >> 32;
  t as i32
}

/*************************************************
* Name:        reduce32
*
* Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
*              compute r \equiv a (mod Q) such that -6283009 <= r <= 6283007.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
pub fn reduce32(a: i32) -> i32 {
  let mut t = (a + (1 << 22)) >> 23;
  t = a - t * Q as i32;
  t
}

/*************************************************
* Name:        caddq
*
* Description: Add Q if input coefficient is negative.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
pub fn caddq(a: i32) -> i32 {
  a + ((a >> 31) & Q as i32)
}

/*************************************************
* Name:        freeze
*
* Description: For finite field element a, compute standard
*              representative r = a mod Q.
*
* Arguments:   - uint32_t: finite field element a
*
* Returns r.
**************************************************/
pub fn _freeze(mut a: i32) -> i32 {
  a = reduce32(a);
  a = caddq(a);
  a
}