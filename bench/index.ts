// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import Benchmark from 'benchmark'
import { Crypto } from '@peculiar/webcrypto'
import { benchGroup } from './group.bench.js'
import { benchOPRF } from './oprf.bench.js'

if (typeof crypto === 'undefined') {
    global.crypto = new Crypto()
}

async function bench() {
    const bs = new Benchmark.Suite()

    for (const f of [benchGroup, benchOPRF]) {
        await f(bs)
    }

    try {
        bs.on('cycle', (ev: Benchmark.Event) => {
            console.log(String(ev.target))
        })
        bs.run({ async: false })
    } catch (e: unknown) {
        console.log('Error: ' + (e as Error).message)
        console.log('Stack: ' + (e as Error).stack)
    }
}

bench()
