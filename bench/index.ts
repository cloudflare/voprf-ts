// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import Benchmark from 'benchmark'
import { benchGroup } from './group.bench.js'
import { benchOPRF } from './oprf.bench.js'
import { webcrypto } from 'node:crypto'

if (typeof crypto === 'undefined') {
    global.crypto = webcrypto as unknown as Crypto
}

async function bench() {
    const bs = new Benchmark.Suite()

    await benchOPRF(bs)
    await benchGroup(bs)

    bs.on('cycle', (ev: Benchmark.Event) => {
        console.log(String(ev.target))
    })

    bs.run({ async: false })
}

bench().catch((e: Error) => {
    console.log(`Error: ${e.message}`)
    console.log(`Stack: ${e.stack}`)
    process.exit(1)
})
