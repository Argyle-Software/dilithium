<p align="center">
  <img src="https://github.com/Argyle-Software/dilithium/blob/master/dilithium.png"/>
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

this repository is not available on npm at this moment

## Usage 

```js
import * as dilithium from "pqc_dilithium";

// Generate Keypair
let keys = dilithium.keypair();
const pubKey = keys.pubkey;
const privKey = keys.secret;

// Sign a message
const msg = new TextEncoder().encode("message")
let sign = keys.sign(msg);

// Verify a signature

let result = dilithium.verify(sign, msg, pubKey)

var assert = require('assert');

assert.equal(result, true)

// Valid input lengths are found in the `Params` class
assert.equal(pubKey.length, kyber.Params.publicKeyBytes);
assert.equal(privKey.length, kyber.Params.secretKeyBytes);
assert.equal(sign.length,  kyber.Params.signBytes);

```
