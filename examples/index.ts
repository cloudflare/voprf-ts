// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { oprfExample } from './oprf.js'
import { poprfExample } from './poprf.js'
import { voprfExample } from './voprf.js'
import { webcrypto } from 'node:crypto'

if (typeof crypto === 'undefined') {
    global.crypto = webcrypto as unknown as Crypto
}

async function examples() {
    await oprfExample()
    await voprfExample()
    await poprfExample()
}

examples()
    .then(() => {
        process.exit(0)
    })
    .catch((err) => {
        console.error(err)
        process.exit(1)
    })
