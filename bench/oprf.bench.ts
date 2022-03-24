// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    OPRFClient,
    OPRFServer,
    Oprf,
    POPRFClient,
    POPRFServer,
    VOPRFClient,
    VOPRFServer,
    generatePublicKey,
    randomPrivateKey
} from '../src/index.js'

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
    const bs = new Benchmark.Suite()
    const input = te.encode('This is the client input')
    let server: OPRFServer | VOPRFServer | POPRFServer
    let client: OPRFClient | VOPRFClient | POPRFClient

    for (const [mode, m] of Object.entries(Oprf.Mode)) {
        for (const [suite, id] of Object.entries(Oprf.Suite)) {
            const privateKey = await randomPrivateKey(id)
            const publicKey = generatePublicKey(id, privateKey)

            switch (m) {
                case Oprf.Mode.OPRF:
                    server = new OPRFServer(id, privateKey)
                    client = new OPRFClient(id)
                    break

                case Oprf.Mode.VOPRF:
                    server = new VOPRFServer(id, privateKey)
                    client = new VOPRFClient(id, publicKey)
                    break
                case Oprf.Mode.POPRF:
                    server = new POPRFServer(id, privateKey)
                    client = new POPRFClient(id, publicKey)
                    break
            }

            const [finData, evalReq] = await client.blind(input)
            const evaluatedElement = await server.evaluate(evalReq)
            const prefix = mode + '/' + suite + '/'

            bs.add(
                prefix + 'blind   ',
                asyncFn(() => client.blind(input))
            )
            bs.add(
                prefix + 'evaluate',
                asyncFn(() => server.evaluate(evalReq))
            )
            bs.add(
                prefix + 'finalize',
                asyncFn(() => client.finalize(finData, evaluatedElement))
            )
        }
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

benchOPRF()
