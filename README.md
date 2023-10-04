[![NPM](https://img.shields.io/npm/v/@cloudflare/voprf-ts?style=plastic)](https://www.npmjs.com/package/@cloudflare/voprf-ts) [![NPM](https://img.shields.io/npm/l/@cloudflare/voprf-ts?style=plastic)](LICENSE.txt)

[![NPM](https://nodei.co/npm/@cloudflare/voprf-ts.png)](https://www.npmjs.com/package/@cloudflare/voprf-ts)

# voprf-ts: A TypeScript Library for Oblivious Pseudorandom Functions (OPRF).

An **Oblivious Pseudorandom Function (OPRF)** is a two-party protocol between a client and server for computing the output of a Pseudorandom Function (PRF).

The server provides the PRF secret key, and the client provides the PRF input.
At the end of the protocol, the client learns the PRF output without learning anything about the PRF secret key, and the server learns neither the PRF input nor output.

A **verifiable OPRF (VOPRF)** ensures clients can verify that the server used a specific private key during the execution of the protocol.

A **partially-oblivious (POPRF)** extends a VOPRF allowing the client and server to provide public shared input to the PRF computation.

This library supports all three modes:
```js
Oprf.Mode.OPRF
Oprf.Mode.VOPRF
Oprf.Mode.POPRF
```
and supports three suites corresponding to the underlying group and hash used:
```js
Oprf.Suite.P256_SHA256
Oprf.Suite.P384_SHA384
Oprf.Suite.P521_SHA512
```

**Specification:** Compliant with IETF [draft-irtf-cfrg-voprf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/) and tests vectors match with [v21](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21).

### Usage

#### Step 1

First set up a client and a server. In this case, we use the VOPRF mode with suite P384-SHA384.

```js
import {
    Oprf, VOPRFClient, VOPRFServer, generatePublicKey, randomPrivateKey
} from '@cloudflare/voprf-ts';

const suite = Oprf.Suite.P384_SHA384;
const privateKey = await randomPrivateKey(suite);
const publicKey = generatePublicKey(suite, privateKey);

const server = new VOPRFServer(suite, privateKey);
const client = new VOPRFClient(suite, publicKey);
```

#### Step 2

The client prepares arbitrary input[s] that will be batch evaluated by the server. The blinding method produces an evaluation request, and some finalization data to be used later. Then, the client sends the evaluation request to the server.

```js
const input = new TextEncoder().encode("This is the client's input");
const batch = [input]
const [finData, evalReq] = await client.blind(batch);
```

#### Step 3

Once the server received the evaluation request, it responds to the client with an evaluation.

```js
const evaluation = await server.blindEvaluate(evalReq);
```

#### Step 4

Finally, the client can produce the output[s] of the OPRF protocol using the server's evaluation and the finalization data from the second step. If the mode is verifiable, this step allows the client to check the proof that the server used the expected private key for the evaluation.

```js
// Get output matching first input of batch
const [output] = await client.finalize(finData, evaluation);
```

### Support for @noble Crypto backend (faster & ristretto/decaf)

With this library, you have the flexibility to switch out the cryptographic
backend to`@cloudflare/voprf-ts/crypto-noble`. It has much better performance
and provides support for Ristretto and Decaf groups:

```js
Oprf.Suite.RISTRETTO255_SHA512
Oprf.Suite.DECAF448_SHAKE256
```

Before doing so, be aware of the following:

- The `@noble/curves` library uses native JavaScript `BigInt` for arithmetic
  operations, which are non-constant time by nature. More importantly, the
  noble libraries use constant time(CT) algorithms.

- Before utilizing the `CryptoNoble` backend, you need to install a couple of
  optional dependencies: `@noble/curves` and `@noble/hashes`.

You can install dependencies via:

```bash
npm install @noble/curves @noble/hashes
```

Once installed, here's how to use:

```javascript
import { Oprf } from '@cloudflare/voprf-ts';
import { CryptoNoble } from '@cloudflare/voprf-ts/crypto-noble';

// Override the default Oprf.Crypto with CryptoNoble 
Oprf.Crypto = CryptoNoble; // Aware of BigInt implications for your use case

console.log(Oprf.Crypto.Group.supportedGroups);
// Expected output: [ 'ristretto255', 'decaf448', 'P-256', 'P-384', 'P-521' ]

// Use the library as normal
```

### Development

| Task            | NPM scripts          |
|-----------------|----------------------|
| Installing      | `$ npm ci`           |
| Building        | `$ npm run build`    |
| Unit Tests      | `$ npm run test`     |
| Examples        | `$ npm run examples` |
| Benchmarking    | `$ npm run bench`    |
| Code Linting    | `$ npm run lint`     |
| Code Formatting | `$ npm run format`   |


**Dependencies**

This project uses the Stanford Javascript Crypto Library [sjcl](https://github.com/bitwiseshiftleft/sjcl). Support for elliptic curves must be enabled by this compilation step, which produces the necessary files inside the [src/sjcl](./src/sjcl) folder.

```sh
 $ make -f sjcl.Makefile
```

### License

The project is licensed under the [BSD-3-Clause License](LICENSE.txt).
