<div align="center">

  <h1>Web Assembly Demo</h1>

  <strong>A basic example of using the pqc_dilithium npm module</strong> 



</div>


### Installation

From this folder: 

```shell
npm install
```

### Run
```
npm run start
```

The demo is at [localhost:8080](localhost:8080)


### Library Usage

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






