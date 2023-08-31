#![allow(clippy::needless_range_loop)]

#[cfg(not(feature = "aes"))]
pub const SHAKE128_RATE: usize = 168;
pub const SHAKE256_RATE: usize = 136;

const NROUNDS: usize = 24;

#[derive(Copy, Clone)]
pub struct KeccakState {
  pub s: [u64; 25],
  pub pos: usize,
}

// Replaces init functions
impl Default for KeccakState {
  fn default() -> Self {
    KeccakState {
      s: [0u64; 25],
      pos: 0usize,
    }
  }
}

impl KeccakState {
  pub fn init(&mut self) {
    self.s.fill(0);
    self.pos = 0;
  }
}

fn rol(a: u64, offset: u64) -> u64 {
  (a << offset) ^ (a >> (64 - offset))
}

/// Load 8 bytes into uint64_t in little-endian order/
pub fn load64(x: &[u8]) -> u64 {
  let mut r = 0u64;
  for i in 0..8 {
    r |= (x[i] as u64) << (8 * i);
  }
  r
}

/// Store a 64-bit integer to array of 8 bytes in little-endian order
pub fn store64(x: &mut [u8], u: u64) {
  for i in 0..8 {
    x[i] = (u >> 8 * i) as u8;
  }
}

/// Keccak round constants
const KECCAKF_ROUNDCONSTANTS: [u64; NROUNDS] = [
  0x0000000000000001u64,
  0x0000000000008082u64,
  0x800000000000808au64,
  0x8000000080008000u64,
  0x000000000000808bu64,
  0x0000000080000001u64,
  0x8000000080008081u64,
  0x8000000000008009u64,
  0x000000000000008au64,
  0x0000000000000088u64,
  0x0000000080008009u64,
  0x000000008000000au64,
  0x000000008000808bu64,
  0x800000000000008bu64,
  0x8000000000008089u64,
  0x8000000000008003u64,
  0x8000000000008002u64,
  0x8000000000000080u64,
  0x000000000000800au64,
  0x800000008000000au64,
  0x8000000080008081u64,
  0x8000000000008080u64,
  0x0000000080000001u64,
  0x8000000080008008u64,
];

/// The Keccak F1600 Permutation
pub fn keccakf1600_statepermute(state: &mut [u64]) {
  //copyFromState(A, state)
  let mut aba = state[0];
  let mut abe = state[1];
  let mut abi = state[2];
  let mut abo = state[3];
  let mut abu = state[4];
  let mut aga = state[5];
  let mut age = state[6];
  let mut agi = state[7];
  let mut ago = state[8];
  let mut agu = state[9];
  let mut aka = state[10];
  let mut ake = state[11];
  let mut aki = state[12];
  let mut ako = state[13];
  let mut aku = state[14];
  let mut ama = state[15];
  let mut ame = state[16];
  let mut ami = state[17];
  let mut amo = state[18];
  let mut amu = state[19];
  let mut asa = state[20];
  let mut ase = state[21];
  let mut asi = state[22];
  let mut aso = state[23];
  let mut asu = state[24];

  for round in (0..NROUNDS).step_by(2) {
    //    prepareTheta
    let mut bca = aba ^ aga ^ aka ^ ama ^ asa;
    let mut bce = abe ^ age ^ ake ^ ame ^ ase;
    let mut bci = abi ^ agi ^ aki ^ ami ^ asi;
    let mut bco = abo ^ ago ^ ako ^ amo ^ aso;
    let mut bcu = abu ^ agu ^ aku ^ amu ^ asu;

    //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
    let mut da = bcu ^ rol(bce, 1);
    let mut de = bca ^ rol(bci, 1);
    let mut di = bce ^ rol(bco, 1);
    let mut d_o = bci ^ rol(bcu, 1);
    let mut du = bco ^ rol(bca, 1);

    aba ^= da;
    bca = aba;
    age ^= de;
    bce = rol(age, 44);
    aki ^= di;
    bci = rol(aki, 43);
    amo ^= d_o;
    bco = rol(amo, 21);
    asu ^= du;
    bcu = rol(asu, 14);
    let mut eba = bca ^ ((!bce) & bci);
    eba ^= KECCAKF_ROUNDCONSTANTS[round];
    let mut ebe = bce ^ ((!bci) & bco);
    let mut ebi = bci ^ ((!bco) & bcu);
    let mut ebo = bco ^ ((!bcu) & bca);
    let mut ebu = bcu ^ ((!bca) & bce);

    abo ^= d_o;
    bca = rol(abo, 28);
    agu ^= du;
    bce = rol(agu, 20);
    aka ^= da;
    bci = rol(aka, 3);
    ame ^= de;
    bco = rol(ame, 45);
    asi ^= di;
    bcu = rol(asi, 61);
    let mut ega = bca ^ ((!bce) & bci);
    let mut ege = bce ^ ((!bci) & bco);
    let mut egi = bci ^ ((!bco) & bcu);
    let mut ego = bco ^ ((!bcu) & bca);
    let mut egu = bcu ^ ((!bca) & bce);

    abe ^= de;
    bca = rol(abe, 1);
    agi ^= di;
    bce = rol(agi, 6);
    ako ^= d_o;
    bci = rol(ako, 25);
    amu ^= du;
    bco = rol(amu, 8);
    asa ^= da;
    bcu = rol(asa, 18);
    let mut eka = bca ^ ((!bce) & bci);
    let mut eke = bce ^ ((!bci) & bco);
    let mut eki = bci ^ ((!bco) & bcu);
    let mut eko = bco ^ ((!bcu) & bca);
    let mut eku = bcu ^ ((!bca) & bce);

    abu ^= du;
    bca = rol(abu, 27);
    aga ^= da;
    bce = rol(aga, 36);
    ake ^= de;
    bci = rol(ake, 10);
    ami ^= di;
    bco = rol(ami, 15);
    aso ^= d_o;
    bcu = rol(aso, 56);
    let mut ema = bca ^ ((!bce) & bci);
    let mut eme = bce ^ ((!bci) & bco);
    let mut emi = bci ^ ((!bco) & bcu);
    let mut emo = bco ^ ((!bcu) & bca);
    let mut emu = bcu ^ ((!bca) & bce);

    abi ^= di;
    bca = rol(abi, 62);
    ago ^= d_o;
    bce = rol(ago, 55);
    aku ^= du;
    bci = rol(aku, 39);
    ama ^= da;
    bco = rol(ama, 41);
    ase ^= de;
    bcu = rol(ase, 2);
    let mut esa = bca ^ ((!bce) & bci);
    let mut ese = bce ^ ((!bci) & bco);
    let mut esi = bci ^ ((!bco) & bcu);
    let mut eso = bco ^ ((!bcu) & bca);
    let mut esu = bcu ^ ((!bca) & bce);

    //    prepareTheta
    bca = eba ^ ega ^ eka ^ ema ^ esa;
    bce = ebe ^ ege ^ eke ^ eme ^ ese;
    bci = ebi ^ egi ^ eki ^ emi ^ esi;
    bco = ebo ^ ego ^ eko ^ emo ^ eso;
    bcu = ebu ^ egu ^ eku ^ emu ^ esu;

    //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
    da = bcu ^ rol(bce, 1);
    de = bca ^ rol(bci, 1);
    di = bce ^ rol(bco, 1);
    d_o = bci ^ rol(bcu, 1);
    du = bco ^ rol(bca, 1);

    eba ^= da;
    bca = eba;
    ege ^= de;
    bce = rol(ege, 44);
    eki ^= di;
    bci = rol(eki, 43);
    emo ^= d_o;
    bco = rol(emo, 21);
    esu ^= du;
    bcu = rol(esu, 14);
    aba = bca ^ ((!bce) & bci);
    aba ^= KECCAKF_ROUNDCONSTANTS[round + 1];
    abe = bce ^ ((!bci) & bco);
    abi = bci ^ ((!bco) & bcu);
    abo = bco ^ ((!bcu) & bca);
    abu = bcu ^ ((!bca) & bce);

    ebo ^= d_o;
    bca = rol(ebo, 28);
    egu ^= du;
    bce = rol(egu, 20);
    eka ^= da;
    bci = rol(eka, 3);
    eme ^= de;
    bco = rol(eme, 45);
    esi ^= di;
    bcu = rol(esi, 61);
    aga = bca ^ ((!bce) & bci);
    age = bce ^ ((!bci) & bco);
    agi = bci ^ ((!bco) & bcu);
    ago = bco ^ ((!bcu) & bca);
    agu = bcu ^ ((!bca) & bce);

    ebe ^= de;
    bca = rol(ebe, 1);
    egi ^= di;
    bce = rol(egi, 6);
    eko ^= d_o;
    bci = rol(eko, 25);
    emu ^= du;
    bco = rol(emu, 8);
    esa ^= da;
    bcu = rol(esa, 18);
    aka = bca ^ ((!bce) & bci);
    ake = bce ^ ((!bci) & bco);
    aki = bci ^ ((!bco) & bcu);
    ako = bco ^ ((!bcu) & bca);
    aku = bcu ^ ((!bca) & bce);

    ebu ^= du;
    bca = rol(ebu, 27);
    ega ^= da;
    bce = rol(ega, 36);
    eke ^= de;
    bci = rol(eke, 10);
    emi ^= di;
    bco = rol(emi, 15);
    eso ^= d_o;
    bcu = rol(eso, 56);
    ama = bca ^ ((!bce) & bci);
    ame = bce ^ ((!bci) & bco);
    ami = bci ^ ((!bco) & bcu);
    amo = bco ^ ((!bcu) & bca);
    amu = bcu ^ ((!bca) & bce);

    ebi ^= di;
    bca = rol(ebi, 62);
    ego ^= d_o;
    bce = rol(ego, 55);
    eku ^= du;
    bci = rol(eku, 39);
    ema ^= da;
    bco = rol(ema, 41);
    ese ^= de;
    bcu = rol(ese, 2);
    asa = bca ^ ((!bce) & bci);
    ase = bce ^ ((!bci) & bco);
    asi = bci ^ ((!bco) & bcu);
    aso = bco ^ ((!bcu) & bca);
    asu = bcu ^ ((!bca) & bce);
  }

  state[0] = aba;
  state[1] = abe;
  state[2] = abi;
  state[3] = abo;
  state[4] = abu;
  state[5] = aga;
  state[6] = age;
  state[7] = agi;
  state[8] = ago;
  state[9] = agu;
  state[10] = aka;
  state[11] = ake;
  state[12] = aki;
  state[13] = ako;
  state[14] = aku;
  state[15] = ama;
  state[16] = ame;
  state[17] = ami;
  state[18] = amo;
  state[19] = amu;
  state[20] = asa;
  state[21] = ase;
  state[22] = asi;
  state[23] = aso;
  state[24] = asu;
}

/// Absorb step of Keccak; incremental.
fn keccak_absorb(
  state: &mut KeccakState,
  r: usize,
  input: &[u8],
  mut inlen: usize,
) {
  let mut idx = 0;
  let mut pos = state.pos;
  while pos + inlen >= r {
    for i in pos..r {
      state.s[i / 8] ^= (input[idx] as u64) << 8 * (i % 8);
      idx += 1;
    }
    inlen -= r - pos;
    keccakf1600_statepermute(&mut state.s);
    pos = 0;
  }
  let mut i = pos;
  while i < pos + inlen {
    state.s[i / 8] ^= (input[idx] as u64) << 8 * (i % 8);
    idx += 1;
    i += 1
  }
  state.pos = i;
}

/// Finalize absorb step.
fn keccak_finalize(s: &mut [u64; 25], pos: usize, r: usize, p: u8) {
  s[pos / 8] ^= (p as u64) << 8 * (pos % 8);
  s[r / 8 - 1] ^= 1u64 << 63;
}

/// Squeeze step of Keccak. Squeezes arbitratrily many bytes.
///  Modifies the state. Can be called multiple times to keep
///  squeezing, i.e., is incremental.
///
// Returns new position pos in current block
fn keccak_squeeze(
  out: &mut [u8],
  mut outlen: usize,
  s: &mut [u64; 25],
  mut pos: usize,
  r: usize,
) -> usize {
  while outlen != 0 {
    if pos == r {
      keccakf1600_statepermute(s);
      pos = 0;
    }
    let mut i = pos;
    let mut idx = 0;
    while i < r && i < pos + outlen {
      out[idx] = (s[i / 8] >> 8 * (i % 8)) as u8;
      idx += 1;
      i += 1;
    }
    outlen -= i - pos;
    pos = i;
  }

  return pos;
}

/// Absorb step of Keccak;
/// non-incremental, starts by zeroeing the state.
fn keccak_absorb_once(
  s: &mut [u64; 25],
  r: usize,
  input: &[u8],
  mut inlen: usize,
  p: u8,
) {
  s.fill(0);
  let mut idx = 0;
  while inlen >= r {
    for i in 0..r / 8 {
      s[i] ^= load64(&input[idx + 8 * i..]);
    }
    idx += r;
    inlen -= r;
    keccakf1600_statepermute(s);
  }

  for i in 0..inlen {
    s[i / 8] ^= (input[idx + i] as u64) << 8 * (i % 8);
  }

  s[inlen / 8] ^= (p as u64) << 8 * (inlen % 8);
  s[(r - 1) / 8] ^= 1u64 << 63;
}

/// Squeeze step of Keccak. Squeezes full blocks of r bytes each.
///  Modifies the state. Can be called multiple times to keep
///  squeezing, i.e., is incremental. Assumes zero bytes of current
///  block have already been squeezed.
fn keccak_squeezeblocks(
  out: &mut [u8],
  mut nblocks: usize,
  s: &mut [u64],
  r: usize,
) {
  let mut idx = 0usize;
  while nblocks > 0 {
    keccakf1600_statepermute(s);
    for i in 0..(r >> 3) {
      store64(&mut out[idx + 8 * i..], s[i])
    }
    idx += r;
    nblocks -= 1;
  }
}

/// Description: Absorb step of the SHAKE128 XOF; incremental.
#[cfg(not(feature = "aes"))]
pub fn shake128_absorb(state: &mut KeccakState, input: &[u8], inlen: usize) {
  keccak_absorb(state, SHAKE128_RATE, input, inlen);
}

/// Finalize absorb step of the SHAKE128 XOF.
#[cfg(not(feature = "aes"))]
pub fn shake128_finalize(state: &mut KeccakState) {
  keccak_finalize(&mut state.s, state.pos as usize, SHAKE128_RATE, 0x1F);
  state.pos = SHAKE128_RATE;
}

/// Squeeze step of SHAKE128 XOF. Squeezes full blocks of
///  SHAKE128_RATE bytes each. Can be called multiple times
///  to keep squeezing. Assumes new block has not yet been
///  started (state->pos = SHAKE128_RATE).
#[cfg(not(feature = "aes"))]
pub fn shake128_squeezeblocks(
  output: &mut [u8],
  nblocks: usize,
  s: &mut KeccakState,
) {
  keccak_squeezeblocks(output, nblocks, &mut s.s, SHAKE128_RATE);
}

/// Absorb step of the SHAKE256 XOF; incremental.
pub fn shake256_absorb(state: &mut KeccakState, input: &[u8], inlen: usize) {
  keccak_absorb(state, SHAKE256_RATE, input, inlen);
}

/// Finalize absorb step of the SHAKE256 XOF.*/
pub fn shake256_finalize(state: &mut KeccakState) {
  keccak_finalize(&mut state.s, state.pos, SHAKE256_RATE, 0x1F);
  state.pos = SHAKE256_RATE;
}

///Squeeze step of SHAKE256 XOF. Squeezes arbitraily many
/// bytes. Can be called multiple times to keep squeezing.
pub fn shake256_squeeze(
  out: &mut [u8],
  outlen: usize,
  state: &mut KeccakState,
) {
  state.pos =
    keccak_squeeze(out, outlen, &mut state.s, state.pos, SHAKE256_RATE);
}
/// Initialize, absorb into and finalize SHAKE256 XOF; non-incremental.
pub fn shake256_absorb_once(
  state: &mut KeccakState,
  input: &[u8],
  inlen: usize,
) {
  keccak_absorb_once(&mut state.s, SHAKE256_RATE, input, inlen, 0x1F);
  state.pos = SHAKE256_RATE;
}

/// Squeeze step of SHAKE256 XOF. Squeezes full blocks of
///              SHAKE256_RATE bytes each. Can be called multiple times
///              to keep squeezing. Assumes next block has not yet been
///              started (state.pos = SHAKE256_RATE).
pub fn shake256_squeezeblocks(
  out: &mut [u8],
  nblocks: usize,
  state: &mut KeccakState,
) {
  keccak_squeezeblocks(out, nblocks, &mut state.s, SHAKE256_RATE);
}

/// SHAKE256 XOF with non-incremental API
pub fn shake256(
  output: &mut [u8],
  mut outlen: usize,
  input: &[u8],
  inlen: usize,
) {
  let mut state = KeccakState::default();

  shake256_absorb_once(&mut state, input, inlen);
  let nblocks = outlen / SHAKE256_RATE;
  shake256_squeezeblocks(output, nblocks, &mut state);
  outlen -= nblocks * SHAKE256_RATE;
  let idx = nblocks * SHAKE256_RATE;
  shake256_squeeze(&mut output[idx..], outlen, &mut state);
}
