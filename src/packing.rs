use crate::{
  params::*,
  polyvec::*,
  poly::*, SigError
};

/*************************************************
* Name:        pack_pk
*
* Description: Bit-pack public key pk = (rho, t1).
*
* Arguments:   - uint8_t pk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const polyveck *t1: pointer to vector t1
**************************************************/
pub fn pack_pk(pk: &mut[u8], rho: &[u8], t1: &Polyveck) {
  pk[..SEEDBYTES].copy_from_slice(&rho[..SEEDBYTES]);
  for i in 0..K {
    polyt1_pack(&mut pk[SEEDBYTES+i*POLYT1_PACKEDBYTES..], &t1.vec[i]);
  }
}

/*************************************************
* Name:        unpack_pk
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const polyveck *t1: pointer to output vector t1
*              - uint8_t pk[]: byte array containing bit-packed pk
**************************************************/
pub fn unpack_pk(rho: &mut[u8], t1: &mut Polyveck, pk: &[u8]) {
  rho[..SEEDBYTES].copy_from_slice(&pk[..SEEDBYTES]);
  for i in 0..K {
    polyt1_unpack(&mut t1.vec[i], &pk[SEEDBYTES+i*POLYT1_PACKEDBYTES..])
  }
}

/*************************************************
* Name:        pack_sk
*
* Description: Bit-pack secret key sk = (rho, key, tr, s1, s2, t0).
*
* Arguments:   - uint8_t sk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const uint8_t key[]: byte array containing key
*              - const uint8_t tr[]: byte array containing tr
*              - const polyvecl *s1: pointer to vector s1
*              - const polyveck *s2: pointer to vector s2
*              - const polyveck *t0: pointer to vector t0
**************************************************/
pub fn pack_sk(
  sk: &mut[u8], 
  rho: &[u8], 
  tr: &[u8],
  key: &[u8], 
  t0: &Polyveck,
  s1: &Polyvecl,
  s2: &Polyveck
)
{
  let mut idx = 0usize;

  sk[idx..SEEDBYTES].copy_from_slice(&rho[0..SEEDBYTES]);
  idx += SEEDBYTES;

  sk[idx..idx+SEEDBYTES].copy_from_slice(&key[0..SEEDBYTES]);
  idx += SEEDBYTES;

  sk[idx..idx+SEEDBYTES].copy_from_slice(&tr[0..SEEDBYTES]);
  idx += SEEDBYTES;

  for i in 0..L {
    polyeta_pack(&mut sk[idx+i*POLYETA_PACKEDBYTES..], &s1.vec[i]);
  }
  idx += L*POLYETA_PACKEDBYTES;

  for i in 0..K {
    polyeta_pack(&mut sk[idx+i*POLYETA_PACKEDBYTES..], &s2.vec[i]);
  }
  idx += K*POLYETA_PACKEDBYTES;

  for i in 0..K {
    polyt0_pack(&mut sk[idx+i*POLYT0_PACKEDBYTES..], &t0.vec[i]);
  }
}

/*************************************************
* Name:        unpack_sk
*
* Description: Unpack secret key sk = (rho, key, tr, s1, s2, t0).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const uint8_t key[]: output byte array for key
*              - const uint8_t tr[]: output byte array for tr
*              - const polyvecl *s1: pointer to output vector s1
*              - const polyveck *s2: pointer to output vector s2
*              - const polyveck *r0: pointer to output vector t0
*              - uint8_t sk[]: byte array containing bit-packed sk
**************************************************/
pub fn unpack_sk(
  rho: &mut[u8],
  tr: &mut[u8],
  key: &mut[u8],
  t0: &mut Polyveck,
  s1: &mut Polyvecl,
  s2: &mut Polyveck,
  sk: &[u8]
)
{
  let mut idx = 0usize;

  rho[..SEEDBYTES].copy_from_slice(&sk[..SEEDBYTES]);
  idx += SEEDBYTES;

  key[..SEEDBYTES].copy_from_slice(&sk[idx..idx+SEEDBYTES]);
  idx += SEEDBYTES;

  tr[..SEEDBYTES].copy_from_slice(&sk[idx..idx+SEEDBYTES]);
  idx += SEEDBYTES;

  for i in 0..L {
    polyeta_unpack(&mut s1.vec[i], &sk[idx+i*POLYETA_PACKEDBYTES..]);
  }
  idx += L*POLYETA_PACKEDBYTES;

  for i in 0..K {
    polyeta_unpack(&mut s2.vec[i], &sk[idx+i*POLYETA_PACKEDBYTES..]);    
  }
  idx += K*POLYETA_PACKEDBYTES;

  for i in 0..K {
    polyt0_unpack(&mut t0.vec[i], &sk[idx+i*POLYT0_PACKEDBYTES..]);
  }
}

/*************************************************
* Name:        pack_sig
*
* Description: Bit-pack signature sig = (c, z, h).
*
* Arguments:   - uint8_t sig[]: output byte array
*              - const uint8_t *c: pointer to challenge hash length SEEDBYTES
*              - const polyvecl *z: pointer to vector z
*              - const polyveck *h: pointer to hint vector h
**************************************************/
pub fn pack_sig(sig: &mut[u8], c: Option< &[u8]>, z: &Polyvecl, h: &Polyveck) {


  let mut idx = 0usize;

  if let Some(challenge) = c {
    sig[..SEEDBYTES].copy_from_slice(&challenge[..SEEDBYTES]);
  }

  idx+= SEEDBYTES;

  for i in 0..L {
    polyz_pack(&mut sig[idx+i*POLYZ_PACKEDBYTES..], &z.vec[i]);
  }
  idx +=  L*POLYZ_PACKEDBYTES;
  // Encode H
  sig[idx..idx + OMEGA + K ].copy_from_slice(&[0u8; OMEGA + K]);

  let mut k = 0;
  for i in 0..K {
    for j in 0..N {
      if h.vec[i].coeffs[j] != 0 {
        sig[idx + k] = j as u8;
        k += 1;
      }
    }
    sig[idx + OMEGA + i] = k as u8;
  }
}

/*************************************************
* Name:        unpack_sig
*
* Description: Unpack signature sig = (z, h, c).
*
* Arguments:   - polyvecl *z: pointer to output vector z
*              - polyveck *h: pointer to output hint vector h
*              - poly *c: pointer to output challenge polynomial
*              - const uint8_t sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
pub fn unpack_sig(
  c: &mut[u8], 
  z: &mut Polyvecl, 
  h: &mut Polyveck, 
  sig: &[u8]
) -> Result<(), SigError> 
{
  let mut idx = 0usize;

  c[..SEEDBYTES].copy_from_slice(&sig[..SEEDBYTES]);
  idx+= SEEDBYTES;

  for i in 0..L {
    polyz_unpack(&mut z.vec[i], &sig[idx+ i*POLYZ_PACKEDBYTES..]);
  }
  idx += L * POLYZ_PACKEDBYTES;

  // Decode h
  let mut k = 0usize; 
  for i in 0..K {
    if sig[idx + OMEGA + i] < k as u8 || sig[idx + OMEGA + i] > OMEGA_U8 {
      return Err(SigError::Input)
    }
    for j in k..sig[idx + OMEGA + i] as usize {
      // Coefficients are ordered for strong unforgeability
      if j > k && sig[idx + j as usize] <= sig[idx + j as usize - 1] {
        return Err(SigError::Input)
      }
      h.vec[i].coeffs[sig[idx + j] as usize] = 1;
    }
    k = sig[idx + OMEGA + i] as usize;
  }

  // Extra indices are zero for strong unforgeability
  for j in k..OMEGA {
    if sig[idx + j as usize] > 0 {
      return Err(SigError::Input)
    }
  }

  Ok(())
}