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

describe.each(Object.entries(Oprf.Mode))('protocol', (modeName, mode) => {
    describe.each(Object.entries(Oprf.Suite))(`${modeName}`, (suiteName, id) => {
        let server: OPRFServer | VOPRFServer | POPRFServer
        let client: OPRFClient | VOPRFClient | POPRFClient

        beforeAll(async () => {
            const privateKey = await randomPrivateKey(id)
            const publicKey = generatePublicKey(id, privateKey)
            switch (mode) {
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
        })

        it(`${suiteName}`, async () => {
            // Client                                       Server
            // ====================================================
            // Client
            // blind, blindedElement = Blind(input)
            const input = new TextEncoder().encode('This is the client input')
            const [finData, evalReq] = await client.blind(input)
            //             evalReq
            //       ------------------>>
            //                                              Server
            //               evaluation = Evaluate(evalReq, info*)
            const evaluation = await server.evaluate(evalReq)
            //            evaluation
            //       <<------------------
            //
            // Client
            // output = Finalize(finData, evaluation, info*)
            //
            const output = await client.finalize(finData, evaluation)
            expect(output).toHaveLength(Oprf.getOprfSize(id))

            const serverOutput = await server.fullEvaluate(input)
            expect(output).toStrictEqual(serverOutput)

            const success = await server.verifyFinalize(input, output)
            expect(success).toBe(true)
        })
    })
})
