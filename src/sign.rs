use crate::{
  params::*,
  packing::*,
  polyvec::*,
  poly::*,
  randombytes::*,
  fips202::*, SigError
};

/*************************************************
* Name:        crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
pub fn crypto_sign_keypair(
  pk: &mut[u8], sk: &mut[u8], seed: Option<&[u8]>
) -> u8 
{
  //TODO: Compile time cfg(test)
  let mut init_seed = [0u8; SEEDBYTES];
  match seed {
    Some(x) => init_seed.copy_from_slice(x),
    None => randombytes(&mut init_seed, SEEDBYTES)
  }; 
  let mut seedbuf = [0u8; 2*SEEDBYTES + CRHBYTES];
  let mut tr = [0u8; SEEDBYTES];
  let (mut rho, mut rhoprime, mut key) = ([0u8; SEEDBYTES],[0u8; CRHBYTES],[0u8; SEEDBYTES]); 
  let mut mat = [Polyvecl::default(); K];
  let mut s1 = Polyvecl::default();
  let (mut s2, mut t1, mut t0) = (Polyveck::default(), Polyveck::default(), Polyveck::default());

  /* Get randomness for rho, rhoprime and key */
  shake256(&mut seedbuf, 2*SEEDBYTES + CRHBYTES, &init_seed, SEEDBYTES);
  rho.copy_from_slice(&seedbuf[..SEEDBYTES]);
  rhoprime.copy_from_slice(&seedbuf[SEEDBYTES..SEEDBYTES+CRHBYTES]);
  key.copy_from_slice(&seedbuf[SEEDBYTES+CRHBYTES..]);

  /* Expand matrix */
  polyvec_matrix_expand(&mut mat, &rho);
  /* Sample short vectors s1 and s2 */
  polyvecl_uniform_eta(&mut s1, &rhoprime, 0);
  polyveck_uniform_eta(&mut s2, &rhoprime, L_U16);

  /* Matrix-vector multiplication */
  let mut s1hat = s1;
  polyvecl_ntt(&mut s1hat);

  polyvec_matrix_pointwise_montgomery(&mut t1, &mat, &s1hat);
  polyveck_reduce(&mut t1);
  polyveck_invntt_tomont(&mut t1);
  

  /* Add error vector s2 */
  polyveck_add(&mut t1, &s2);
  /* Extract t1 and write public key */
  polyveck_caddq(&mut t1); 
  polyveck_power2round(&mut t1, &mut t0);
  pack_pk(pk, &rho, &t1);

  /* Compute H(rho, t1) and write secret key */
  shake256(&mut tr, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  pack_sk(sk, &rho, &tr, &key, &t0, &s1, &s2);

  return 0
}

/*************************************************
* Name:        crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
pub fn crypto_sign_signature(sig: &mut[u8], m: &[u8], sk: &[u8])
{
  // In lieu of the seedbuf variable `key` and `mu` are concatenated
  // to avoid shared mutablity
  let mut keymu = [0u8; SEEDBYTES + CRHBYTES];

  let mut nonce = 0u16;
  let mut mat = [Polyvecl::default(); K];
  let (mut s1, mut y) = (Polyvecl::default(), Polyvecl::default());
  let (mut s2, mut t0) = (Polyveck::default(), Polyveck::default());
  let (mut w1, mut w0) = (Polyveck::default(), Polyveck::default());
  let mut h = Polyveck::default();
  let mut cp = Poly::default();
  let mut state = KeccakState::default(); //shake256_init()
  let mut rho = [0u8; SEEDBYTES];
  let mut tr = [0u8; SEEDBYTES];
  let mut rhoprime = [0u8; CRHBYTES];
  
  
  unpack_sk(&mut rho, &mut tr, &mut keymu[..SEEDBYTES], &mut t0, &mut s1, &mut s2, &sk);

  /* Compute CRH(tr, msg) */
  shake256_absorb(&mut state, &tr, SEEDBYTES);
  shake256_absorb(&mut state, m, m.len());
  shake256_finalize(&mut state);
  shake256_squeeze(&mut keymu[SEEDBYTES..], CRHBYTES, &mut state);

  if RANDOMIZED_SIGNING {
    randombytes(&mut rhoprime, CRHBYTES);
  } else {
    shake256(&mut rhoprime, CRHBYTES, &keymu, SEEDBYTES + CRHBYTES);
  }

    /* Expand matrix and transform vectors */
  polyvec_matrix_expand(&mut mat, &rho);
  polyvecl_ntt(&mut s1);
  polyveck_ntt(&mut s2);
  polyveck_ntt(&mut t0);

  loop {
    /* Sample intermediate vector y */
    polyvecl_uniform_gamma1(&mut y, &rhoprime, nonce);
    nonce += 1;

    /* Matrix-vector multiplication */
    let mut z = y;
    polyvecl_ntt(&mut z);
    polyvec_matrix_pointwise_montgomery(&mut w1, &mat, &z);
    polyveck_reduce(&mut w1);
    polyveck_invntt_tomont(&mut w1);

    /* Decompose w and call the random oracle */
    polyveck_caddq(&mut w1);
    polyveck_decompose(&mut w1, &mut w0);
    polyveck_pack_w1(sig, &w1);

    state.init();
    shake256_absorb(&mut state, &keymu[SEEDBYTES..], CRHBYTES);
    shake256_absorb(&mut state, &sig, K*POLYW1_PACKEDBYTES);
    shake256_finalize(&mut state);
    shake256_squeeze(sig, SEEDBYTES, &mut state);
    poly_challenge(&mut cp, sig);
    poly_ntt(&mut cp);

    /* Compute z, reject if it reveals secret */
    polyvecl_pointwise_poly_montgomery(&mut z, &cp, &s1);
    polyvecl_invntt_tomont(&mut z);
    polyvecl_add(&mut z, &y);
    polyvecl_reduce(&mut z);
    if polyvecl_chknorm(&z, (GAMMA1 - BETA) as i32) > 0 {
      continue;
    }

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
     polyveck_pointwise_poly_montgomery(&mut h, &cp, &s2);
     polyveck_invntt_tomont(&mut h);
     polyveck_sub(&mut w0, &h);
     polyveck_reduce(&mut w0);
    if polyveck_chknorm(&w0, (GAMMA2 - BETA) as i32) > 0 {
      continue;
    }

    /* Compute hints for w1 */
    polyveck_pointwise_poly_montgomery(&mut h, &cp, &t0);
    polyveck_invntt_tomont(&mut h);
    polyveck_reduce(&mut h);
    if polyveck_chknorm(&h, GAMMA2_I32) > 0{
      continue;
    }

    polyveck_add(&mut w0, &h);
    let n = polyveck_make_hint(&mut h, &w0, &w1);
    if n > OMEGA as i32 {
      continue
    }

    /* Write signature */
    pack_sig(sig, None, &z, &h);
    return
  }
}

/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
*                             array with CRYPTO_BYTES + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                               message
*              - const uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - const uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
// pub fn crypto_sign(sm: &mut[u8], smlen: &mut usize, m: &[u8], mlen: usize, sk: &[u8]) -> u8 {
//   for i in 0..mlen {
//     sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
//   }
//   let mut sm2 = vec![0u8; CRYPTO_BYTES + mlen];
//   sm2[CRYPTO_BYTES..].copy_from_slice(&sm[CRYPTO_BYTES..]); //TODO: Cleanup
//   crypto_sign_signature(sm, smlen, &sm2[CRYPTO_BYTES..], mlen, sk);
//   *smlen += mlen;
//   return 0
// }

/*************************************************
* Name:        crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
pub fn crypto_sign_verify(
  sig: &[u8], 
  m: &[u8], 
  pk: &[u8]
) -> Result<(), SigError>
{
  let mut buf = [0u8; K * POLYW1_PACKEDBYTES];
  let mut rho = [0u8; SEEDBYTES];
  let mut mu = [0u8; CRHBYTES];
  let mut c = [0u8; SEEDBYTES];
  let mut c2 = [0u8; SEEDBYTES];
  let mut cp = Poly::default();
  let (mut mat, mut z) = ([Polyvecl::default(); K], Polyvecl::default());
  let (mut t1, mut w1, mut h) = (Polyveck::default(), Polyveck::default(), Polyveck::default());  
  let mut state = KeccakState::default(); // shake256_init()

  if sig.len() != CRYPTO_BYTES {
    return Err(SigError::Input)
  }

  unpack_pk(&mut rho, &mut t1, pk);
  if let Err(e)  = unpack_sig(&mut c, &mut z, &mut h, sig) {
    return Err(e)
  }
  if polyvecl_chknorm(&z, (GAMMA1 - BETA) as i32) > 0 {
    return Err(SigError::Input)
  }

  /* Compute CRH(CRH(rho, t1), msg) */
  shake256(&mut mu, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_absorb(&mut state, &mu, SEEDBYTES);
  shake256_absorb(&mut state, m, m.len());
  shake256_finalize(&mut state);
  shake256_squeeze(&mut mu, CRHBYTES, &mut state);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&mut cp, &c);
  polyvec_matrix_expand(&mut mat, &rho);

  polyvecl_ntt(&mut z);
  polyvec_matrix_pointwise_montgomery(&mut w1, &mat, &z);
  
  poly_ntt(&mut cp);
  polyveck_shiftl(&mut t1);
  polyveck_ntt(&mut t1);
  let t1_2 = t1.clone();
  polyveck_pointwise_poly_montgomery(&mut t1, &cp, &t1_2);

  polyveck_sub(&mut w1, &t1);
  polyveck_reduce(&mut w1);
  polyveck_invntt_tomont(&mut w1);

  /* Reconstruct w1 */
  polyveck_caddq(&mut w1);
  polyveck_use_hint(&mut w1, &h);
  polyveck_pack_w1(&mut buf, &w1);

  /* Call random oracle and verify challenge */
  state.init();
  shake256_absorb(&mut state, &mu, CRHBYTES);
  shake256_absorb(&mut state, &buf, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&mut state);
  shake256_squeeze(&mut c2, SEEDBYTES, &mut state);
  if c != c2 {
    Err(SigError::Verify)
  } else {
    Ok(())
  }
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *m: pointer to output message (allocated
*                            array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const uint8_t *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
// pub fn crypto_sign_open(
//   m: &mut[u8], 
//   sm: &[u8], 
//   smlen: usize,
//   pk: &[u8]
// ) -> i32 
// {
//   if smlen < CRYPTO_BYTES {
//     return badsig(m)
//   }
//   let mlen = smlen - CRYPTO_BYTES;
//   if crypto_sign_verify(sm, CRYPTO_BYTES, &sm[CRYPTO_BYTES..], mlen, pk) > 0 {
//     return badsig(m)
//   } else {
//     for i in 0..mlen {
//       m[i] = sm[CRYPTO_BYTES + i];
//     }
//     return 0
//   }
// }

// fn badsig(m: &mut[u8]) -> i32 {
//   m.fill(0);
//   -1
// }