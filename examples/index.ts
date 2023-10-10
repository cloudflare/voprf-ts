// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { oprfExample } from './oprf.js'
import { poprfExample } from './poprf.js'
import { voprfExample } from './voprf.js'
import { webcrypto } from 'node:crypto'
import { DEFAULT_CRYPTO_PROVIDER } from '../src/cryptoImpl.js'

if (typeof crypto === 'undefined') {
    global.crypto = webcrypto as unknown as Crypto
}

async function examples() {
    const provider = DEFAULT_CRYPTO_PROVIDER

    await oprfExample(provider)
    await voprfExample(provider)
    await poprfExample(provider)
}

examples().catch((e: Error) => {
    console.log(`Error: ${e.message}`)
    console.log(`Stack: ${e.stack}`)
    process.exit(1)
})
