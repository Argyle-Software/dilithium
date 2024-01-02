<p align="center">
  <img src="./dilithium.png"/>
</p>


# Dilithium
[![Build Status](https://github.com/Argyle-Software/dilithium/actions/workflows/kat.yml/badge.svg)](https://github.com/Argyle-Software/dilithium/actions)
[![Crates](https://img.shields.io/crates/v/pqc-dilithium)](https://crates.io/crates/pqc-dilithium)
[![License](https://img.shields.io/crates/l/pqc_dilithium)](https://github.com/Argyle-Software/dilithium/blob/master/LICENSE-MIT)
[![License](https://img.shields.io/crates/l/pqc_dilithium)](https://github.com/Argyle-Software/dilithium/blob/master/LICENSE-APACHE)

A rust implementation of the Dilithium, a KEM standardised by the NIST Post-Quantum Standardization Project.

See the [**features**](#features) section for different options regarding security levels and modes of operation. The default security setting is Dilithium3.

It is recommended to use Dilithium in a hybrid system alongside a traditional signature algorithm such as ed25519. 

**Minimum Supported Rust Version: 1.50.0**

---

## Installation

```shell
cargo add pqc_dilithium
``` 

## Usage 

```rust
use pqc_dilithium::*;
```

### Key Generation
```rust
let keys = Keypair::generate();
assert!(keys.public.len() == PUBLICKEYBYTES);
assert!(keys.expose_secret().len() == SECRETKEYBYTES);
```

### Restoring a Keypair
```rust
use pqc_dilithium::*;
use crate::params::{PUBLICKEYBYTES, SECRETKEYBYTES};
use std::convert::TryInto;

// Assuming you have public and secret key bytes
let public_bytes: Vec<u8> = vec![0u8; PUBLICKEYBYTES]; // Example byte vectors
let secret_bytes: Vec<u8> = vec![0u8; SECRETKEYBYTES];

// Restore the keypair
let restored_keypair = Keypair::new(public_bytes, secret_bytes);
assert!(restored_keypair.is_ok());
```

### Signing 
```rust
let msg = "Hello".as_bytes();
let sig = keys.sign(&msg);
assert!(sig.len() == SIGNBYTES);
```

### Verification
```rust
let sig_verify = verify(&sig, &msg, &keys.public);
assert!(sig_verify.is_ok());
```

---

## AES mode

Dilithium-AES, that uses AES-256 in counter mode instead of SHAKE to 
expand the matrix and the masking vectors, and to sample the secret polynomials.
This offers hardware speedups on certain platforms.

---

## Randomized signing

One may want to consider randomized signatures in situations where the side channel
attacks of [SBB+18, PSS+18] exploiting determinism are applicable. Another situation
where one may want to avoid determinism is when the signer does not wish to reveal the
message that is being signed. While there is no timing leakage of the secret key, there is
timing leakage of the message if the scheme is deterministic. Since the randomness of the
scheme is derived from the message, the number of aborts for a particular message will
always be the same.

---

## Features

By default this library uses Dilithium3

| Name           | Description                                                                                                       |
|----------------|-------------------------------------------------------------------------------------------------------------------|
| mode2          | Uses Dilithium2                                                                                                   |
| mode5          | Uses Dilithium5                                                                                                   |
| aes            | Uses AES256-CTR instead of SHAKE                                                                                  |
| random_signing | Enables randomized signing of messages                                                                            |
| wasm           | For compiling to WASM targets                                                                                     |

---

## Testing 

To run the known answer tests, you'll need to enable the `dilithium_kat` in `RUSTFLAGS` eg.

```shell
RUSTFLAGS="--cfg dilithium_kat" cargo test
```

To run through all possible features use the [`test_matrix.sh`](./tests/test_matrix.sh) script.

---

## Benchmarking

This library uses the criterion benchmarking suite. To use you must enable
`bench` eg.

```shell
RUSTFLAGS="--cfg bench" cargo bench
```

---

## WebAssembly

To compile the wasm files yourself you need to enable the `wasm` feature.

For example, using [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/):

```shell
wasm-pack build -- --features wasm
```

Which will export the wasm, javascript and  typescript files into `./pkg/`. 

To compile a different variant into a separate folder: 
```shell
wasm-pack build --out-dir pkg_mode5/ -- --features "wasm mode5" 
```

There is also a basic html demo in the [www](./www/readme.md) folder.
 
From the www folder run: 

```shell
npm install
npm run start
```

---

## Alternatives

The PQClean project has rust bindings for their C post quantum libraries. 

https://github.com/rustpq/pqcrypto/tree/main/pqcrypto-dilithium

--- 

## About

Dilithium is a digital signature scheme that is strongly secure under chosen message attacks based on the hardness of lattice problems over module lattices. The security notion means that an adversary having access to a signing oracle cannot produce a signature of a message whose signature he hasn't yet seen, nor produce a different signature of a message that he already saw signed. Dilithium has been standardised by the [NIST post-quantum cryptography project](https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022).

The official website: https://pq-crystals.org/dilithium/

Authors of the Dilithium Algorithm: 

* Roberto Avanzi, ARM Limited (DE)
* Joppe Bos, NXP Semiconductors (BE)
* Léo Ducas, CWI Amsterdam (NL)
* Eike Kiltz, Ruhr University Bochum (DE)
* Tancrède Lepoint, SRI International (US)
* Vadim Lyubashevsky, IBM Research Zurich (CH)
* John M. Schanck, University of Waterloo (CA)
* Peter Schwabe, Radboud University (NL)
* Gregor Seiler, IBM Research Zurich (CH)
* Damien Stehle, ENS Lyon (FR)

---

## Contributing

Contributions welcome. For pull requests create a feature fork, by submitting PR's you agree for the code to be dual licensed under MIT/Apache 2.0