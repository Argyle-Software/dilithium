#[cfg(feature = "mode2")]
mod mode_2;
#[cfg(not(any(feature = "mode2", feature = "mode5")))]
mod mode_3;
#[cfg(feature = "mode5")]
mod mode_5;

#[cfg(feature = "mode2")]
pub use mode_2::*;
#[cfg(not(any(feature = "mode2", feature = "mode5")))]
pub use mode_3::*;
#[cfg(feature = "mode5")]
pub use mode_5::*;

pub const SEEDBYTES: usize = 32;
pub const CRHBYTES: usize = 64;
pub const N: usize = 256;
pub const Q: usize = 8380417;
pub const D: usize = 13;
pub const ROOT_OF_UNITY: usize = 1753;

pub const POLYT1_PACKEDBYTES: usize = 320;
pub const POLYT0_PACKEDBYTES: usize = 416;
pub const POLYVECH_PACKEDBYTES: usize = OMEGA + K;

pub const POLYZ_PACKEDBYTES: usize =
  if cfg!(feature = "mode2") { 576 } else { 640 };
pub const POLYW1_PACKEDBYTES: usize =
  if cfg!(feature = "mode2") { 192 } else { 128 };

pub const POLYETA_PACKEDBYTES: usize =
  if cfg!(not(any(feature = "mode2", feature = "mode5"))) {
    128
  } else {
    96
  };

// Concise types to avoid cast cluttering
pub const Q_I32: i32 = Q as i32;
pub const N_U32: u32 = N as u32;
pub const L_U16: u16 = L as u16;
pub const BETA_I32: i32 = BETA as i32;
pub const GAMMA1_I32: i32 = GAMMA1 as i32;
pub const GAMMA2_I32: i32 = GAMMA2 as i32;
pub const OMEGA_U8: u8 = OMEGA as u8;
pub const ETA_I32: i32 = ETA as i32;
pub const GAMMA1_SUB_BETA: i32 = (GAMMA1 - BETA) as i32;

pub const PUBLICKEYBYTES: usize = SEEDBYTES + K * POLYT1_PACKEDBYTES;
pub const SECRETKEYBYTES: usize = 3 * SEEDBYTES
  + L * POLYETA_PACKEDBYTES
  + K * POLYETA_PACKEDBYTES
  + K * POLYT0_PACKEDBYTES;
pub const SIGNBYTES: usize =
  SEEDBYTES + L * POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES;

pub const RANDOMIZED_SIGNING: bool = cfg!(feature = "random_signing");
