// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    type CryptoProvider,
    generatePublicKey,
    getSupportedSuites,
    Oprf,
    OPRFClient,
    OPRFServer,
    POPRFClient,
    POPRFServer,
    randomPrivateKey,
    VOPRFClient,
    VOPRFServer
} from '../src/index.js'

import Benchmark from 'benchmark'

function asyncFn(call: CallableFunction) {
    return {
        defer: true,
        async fn(df: Benchmark.Deferred) {
            await call()
            df.resolve()
        }
    }
}

export async function benchOPRF(crypto: CryptoProvider, bs: Benchmark.Suite) {
    const te = new TextEncoder()
    const input = te.encode('This is the client input')

    for (const [mode, m] of Object.entries(Oprf.Mode)) {
        for (const id of getSupportedSuites(crypto.Group)) {
            const privateKey = await randomPrivateKey(id, crypto)
            const publicKey = generatePublicKey(id, privateKey, crypto)
            let server: OPRFServer | VOPRFServer | POPRFServer
            let client: OPRFClient | VOPRFClient | POPRFClient

            switch (m) {
                case Oprf.Mode.OPRF:
                    server = new OPRFServer(id, privateKey, crypto)
                    client = new OPRFClient(id, crypto)
                    break

                case Oprf.Mode.VOPRF:
                    server = new VOPRFServer(id, privateKey, crypto)
                    client = new VOPRFClient(id, publicKey, crypto)
                    break
                case Oprf.Mode.POPRF:
                    server = new POPRFServer(id, privateKey, crypto)
                    client = new POPRFClient(id, publicKey, crypto)
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
