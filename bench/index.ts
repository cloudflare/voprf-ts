// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import Benchmark from 'benchmark'
import { webcrypto } from 'node:crypto'

import { benchGroup } from './group.bench.js'
import { benchOPRF } from './oprf.bench.js'
import { getCryptoProviders } from './testProviders.js'

import { type CryptoProvider } from '../src/index.js'

if (typeof crypto === 'undefined') {
    Object.assign(global, { crypto: webcrypto })
}

async function bench(provider: CryptoProvider) {
    const bs = new Benchmark.Suite()
    await benchOPRF(provider, bs)
    await benchGroup(provider, bs)

    return new Promise<unknown>((resolve, reject) => {
        bs.on('cycle', (ev: Benchmark.Event) => {
            console.log(`${provider.id}/${String(ev.target)}`)
        })
        bs.on('error', (event: Benchmark.Event) => {
            bs.abort()
            reject(new Error(`error: ${String(event.target)}`))
        })
        bs.on('complete', resolve)

        bs.run({ async: false })
    })
}

async function runBenchmarksSerially() {
    try {
        for (const provider of getCryptoProviders()) {
            await bench(provider)
        }
    } catch (_e) {
        const e = _e as Error
        console.log(`Error: ${e.message}`)
        console.log(`Stack: ${e.stack}`)
        process.exit(1)
    }
}

void runBenchmarksSerially()
