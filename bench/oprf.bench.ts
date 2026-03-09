// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    type CryptoProvider,
    Oprf,
    OPRFClient,
    OPRFServer,
    POPRFServer,
    POPRFClient,
    VOPRFClient,
    VOPRFServer,
    generatePublicKey,
    getSupportedSuites,
    randomPrivateKey
} from '../src/index.js'

import type Benchmark from 'benchmark'

function asyncFn(call: () => Promise<unknown>) {
    return {
        defer: true,
        async fn(df: Benchmark.Deferred) {
            await call()
            df.resolve()
        }
    }
}

export async function benchOPRF(provider: CryptoProvider, bs: Benchmark.Suite) {
    const te = new TextEncoder()
    const input = te.encode('This is the client input')

    for (const [mode, m] of Object.entries(Oprf.Mode)) {
        for (const id of getSupportedSuites(provider.Group)) {
            const privateKey = await randomPrivateKey(id, provider)
            const publicKey = generatePublicKey(id, privateKey, provider)
            let server: OPRFServer | VOPRFServer | POPRFServer
            let client: OPRFClient | VOPRFClient | POPRFClient

            switch (m) {
                case Oprf.Mode.OPRF:
                    server = new OPRFServer(id, privateKey, provider)
                    client = new OPRFClient(id, provider)
                    break

                case Oprf.Mode.VOPRF:
                    server = new VOPRFServer(id, privateKey, provider)
                    client = new VOPRFClient(id, publicKey, provider)
                    break
                case Oprf.Mode.POPRF:
                    server = new POPRFServer(id, privateKey, provider)
                    client = new POPRFClient(id, publicKey, provider)
                    break
            }

            const [finData, evalReq] = await client.blind([input])
            const evaluatedElement = await server.blindEvaluate(evalReq)
            const prefix = mode + '/' + id + '/'

            bs.add(
                prefix + 'blind    ',
                asyncFn(() => client.blind([input]))
            )
            bs.add(
                prefix + 'blindEval',
                asyncFn(() => server.blindEvaluate(evalReq))
            )
            bs.add(
                prefix + 'finalize ',
                asyncFn(() => client.finalize(finData, evaluatedElement))
            )
        }
    }
}
