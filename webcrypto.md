# Web Crypto API for OPRF

----

This is a specification of a [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) for OPRF base mode, which is specified in https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf.

Author: Armando Faz (armfazh@cloudflare.com)

License: BSD-3-Clause

## Contents:

  * [Parameters](#parameters)
  * [OPRF Server side support](#oprf-server-side-support)
  * [API description](#api-description)
    + [Keygen](#keygen)
    + [Evaluate](#evaluate)
    + [importKey](#importkey)
    + [exportKey](#exportkey)


## Parameters

| Group	| namedCurve | Size of scalar (n bytes) | Size of points (n+1 bytes) |
|---|---|---|---|
| P-256 | "P-256" | 32 | 33 |
| P-384 | "P-384" | 48 | 49 |
| P-521 | "P-521" | 66 | 67 |


## OPRF Server side support

This is the expected functionality for an OPRF server.

| OPRF Method | Spec | WebCrypto Method | Comments |
|---|---|---|---|
| Keygen | Section 2.1 | key = crypto.subtle.generateKey(algorithm, extractable, keyUsages) | Use this function for generating an OPRF CryptoKey (private key). Internally, the key stores a scalar k. |
| Evaluate | Section 3.4.1.1 | sig = crypto.subtle.sign(key, msg) | Behind the scenes, this is a scalar multiplication.  key = a CryptoKey containing a scalar k. msg = a compressed point P on the curve (an ArrayBuffer of size n+1) sig = a compressed point kP on the curve (an ArrayBuffer of size n+1) |
| | | crypto.subtle.importKey | Converts raw bytes into an OPRF CryptoKey. During importing, the key can be defined as exportable or not. If exportable,  subtle.export can recover the raw bytes from the OPRF CryptoKey. |
| | | crypto.subtle.exportKey | if exportable, converts a OPRF CryptoKey into raw bytes.|
| | | crypto.subtle.verify (not implemented) | No method is mapped to subtle.verify |


## API description

---


### Keygen

```js
const result = crypto.subtle.generateKey(algorithm, extractable, keyUsages)
```

#### Parameters

```js
algorithm: {
    name: "OPRF",
    namedCurve: "P-256" // one of "P-256", "P-384", "P-521"
}
```

`extractable: true`

`keyUsages: [ "sign" ]`

#### Returns

It returns a `CryptoKey` used only for OPRF signatures.

---

### Evaluate

#### Parameters

```js
const signature = crypto.subtle.sign(algorithm, key, data);
```

```js
algorithm: {
    name: "OPRF"
}
```

`key:` key is a `CryptoKey` imported with subtle.importKey.

`data:` data is an ArrayBuffer containing a compressed point on the curve.

#### Returns

It returns a Promise to an ArrayBufer containing a compressed point on the curve.

---

### importKey

#### Parameters

```js
const result = crypto.subtle.importKey(
    format,
    keyData,
    algorithm,
    extractable,
    keyUsages
);
```

`format: "raw"`

`keyData:` keydata is an ArrayBuffer of length n containing the key.

```js
algorithm: {
    name: "OPRF",
    namedCurve: "P-256" // one of "P-256", "P-384", "P-521"
}
```

`extractable: true`

`keyUsages: [ "sign" ]`

#### Returns

It returns a `CryptoKey` used only for OPRF signatures.

---

### exportKey

#### Parameters

```js
const result = crypto.subtle.exportKey(format, key);
```

`format: "raw"`

`key:` key is a `CryptoKey` used only for OPRF signatures.


#### Returns

It returns an ArrayBuffer of length n containing the key.
