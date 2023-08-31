use crate::params::*;

/// For finite field element a, compute a0, a1 such that
/// a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
/// Assumes a to be standard representative.
///
/// Returns a1.
pub fn power2round(a: i32, a0: &mut i32) -> i32 {
  let a1 = (a + (1 << (D - 1)) - 1) >> D;
  *a0 = a - (a1 << D);
  return a1;
}

/// For finite field element a, compute high and low bits a0, a1 such
/// that a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except
/// if a1 = (Q-1)/ALPHA where we set a1 = 0 and
/// -ALPHA/2 <= a0 = a mod^+ Q - Q < 0. Assumes a to be standard
/// representative.
///
/// Returns a1.
pub fn decompose(a0: &mut i32, a: i32) -> i32 {
  let mut a1 = (a + 127) >> 7;
  if GAMMA2 == (Q - 1) / 32 {
    a1 = (a1 * 1025 + (1 << 21)) >> 22;
    a1 &= 15;
  } else if GAMMA2 == (Q - 1) / 88 {
    a1 = (a1 * 11275 + (1 << 23)) >> 24;
    a1 ^= ((43 - a1) >> 31) & a1;
  }
  *a0 = a - a1 * 2 * GAMMA2_I32;
  *a0 -= (((Q_I32 - 1) / 2 - *a0) >> 31) & Q_I32;
  a1
}

/// Compute hint bit indicating whether the low bits of the
/// input element overflow into the high bits.
///
/// Returns 1 if overflow.
pub fn make_hint(a0: i32, a1: i32) -> u8 {
  if a0 > GAMMA2_I32 || a0 < -GAMMA2_I32 || (a0 == -GAMMA2_I32 && a1 != 0) {
    return 1;
  }
  return 0;
}

/// Correct high bits according to hint.
///
/// Returns corrected high bits.
pub fn use_hint(a: i32, hint: u8) -> i32 {
  let mut a0 = 0i32;
  let a1 = decompose(&mut a0, a);
  if hint == 0 {
    return a1;
  }

  if GAMMA2 == (Q - 1) / 32 {
    if a0 > 0 {
      return (a1 + 1) & 15;
    } else {
      return (a1 - 1) & 15;
    }
  } else {
    if a0 > 0 {
      if a1 == 43 {
        return 0;
      } else {
        return a1 + 1;
      };
    } else {
      if a1 == 0 {
        return 43;
      } else {
        return a1 - 1;
      }
    }
  }
}
