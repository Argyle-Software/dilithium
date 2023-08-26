#!/usr/bin/env node

// Uses CommonJS modules
// Package needs to be built for node:
// wasm-pack build --target nodejs -- features wasm
const dilithium = require("../pkg/pqc_dilithium");
const assert = require("assert");

// Generate Keypair
let keys = dilithium.keypair();
const pubKey = keys.pubkey;
const privKey = keys.secret;

console.log("Public Key Length: " + pubKey.length);
console.log("Secret Key Length: " + privKey.length);

// Sign message
const msg = "Lorem Ipsum";
const msgBytes = new TextEncoder().encode(msg);
let sign = keys.sign(msgBytes);

console.log("Message: " + msg);
console.log("Signature Length: " + sign.length);

// Verify signature
let result = dilithium.verify(sign, msgBytes, pubKey);
assert.equal(result, true, "Signature doesn't match Public Key");
console.log("Sig Verify: " + result);

// Valid input lengths are found in the Params class
assert.equal(pubKey.length, dilithium.Params.publicKeyBytes, "Public Key Length");
assert.equal(privKey.length, dilithium.Params.secretKeyBytes, "Secret Key Length");
assert.equal(sign.length, dilithium.Params.signBytes, "Signature Length");