// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { OPRFClient, OPRFServer, OprfID, randomPrivateKey } from '../src/index.js'

import Benchmark from 'benchmark'
import { Crypto } from '@peculiar/webcrypto'

if (typeof crypto === 'undefined') {
    global.crypto = new Crypto()
}

function asyncFn(call: CallableFunction) {
    return {
        defer: true,
        async fn(df: Benchmark.Deferred) {
            await call()
            df.resolve()
        }
    }
}

async function benchOPRF() {
    const te = new TextEncoder()
    const s = new Benchmark.Suite()
    const input = te.encode('This is the client input')

    for (const id of [OprfID.OPRF_P256_SHA256, OprfID.OPRF_P384_SHA384, OprfID.OPRF_P521_SHA512]) {
        const privateKey = await randomPrivateKey(id)
        const server = new OPRFServer(id, privateKey)
        const client = new OPRFClient(id)
        const { blind, blindedElement } = await client.blind(input)
        const evaluatedElement = await server.evaluate(blindedElement)
        const name = `${OprfID[id as number]}: `

        s.add(
            name + 'blind   ',
            asyncFn(() => client.blind(input))
        )
        s.add(
            name + 'evaluate',
            asyncFn(() => server.evaluate(blindedElement))
        )
        s.add(
            name + 'finalize',
            asyncFn(() => client.finalize(input, blind, evaluatedElement))
        )
    }

    try {
        s.on('cycle', (ev: Benchmark.Event) => {
            console.log(String(ev.target))
        })
        s.run({ async: false })
    } catch (e: unknown) {
        console.log('Error: ' + (e as Error).message)
        console.log('Stack: ' + (e as Error).stack)
    }
}

benchOPRF()
