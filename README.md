# voprf-ts

This is a TypeScript library for Oblivious Pseudorandom Functions (OPRF).

[![NPM](https://nodei.co/npm/@cloudflare/voprf-ts.png)](https://www.npmjs.com/package/@cloudflare/voprf-ts)

### Use

Available at: [@cloudflare/voprf-ts](https://www.npmjs.com/package/@cloudflare/voprf-ts)

```sh
 $ npm install @cloudflare/voprf-ts
```

### Specification

IETF draft [VOPRF v09](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-09)

### Test and Coverage

```sh
 $ npm ci
 $ npm test
```

### Dependencies

It uses the Stanford Javascript Crypto Library [sjcl](https://github.com/bitwiseshiftleft/sjcl). To enable support for elliptic curves a compilation step is required, which produces the necessary files inside the ./src/sjcl folder.

```sh
 $ make -f sjcl.Makefile
```

### License

[BSD-3-Clause](LICENSE.txt)
