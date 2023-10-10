// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    Evaluation,
    EvaluationRequest,
    FinalizeData,
    generatePublicKey,
    Oprf,
    OPRFClient,
    OPRFServer,
    POPRFClient,
    POPRFServer,
    randomPrivateKey,
    VOPRFClient,
    VOPRFServer
} from '../src/index.js'
import { describeCryptoTests } from './describeCryptoTests.js'

import { serdeClass } from './util.js'
import type { Client, Server } from '../src/facade/types.js'

async function testBadProof(
    client: Client,
    server: Server,
    finData: FinalizeData,
    evaluation: Evaluation
) {
    const badEval = Evaluation.deserialize(server.constructDLEQParams(), evaluation.serialize())
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    Object.assign(badEval.proof!, { s: evaluation.proof!.c })
    await expect(client.finalize(finData, badEval)).rejects.toThrow(/proof failed/)
}

describeCryptoTests(({ cryptoProvider, supportedSuites }) => {
    describe.each(Object.entries(Oprf.Mode))('protocol', (modeName, mode) => {
        describe.each(supportedSuites)(`${modeName}`, (id) => {
            let server: Server
            let client: Client

            beforeAll(async () => {
                const privateKey = await randomPrivateKey(id, cryptoProvider)
                const publicKey = generatePublicKey(id, privateKey, cryptoProvider)
                switch (mode) {
                    case Oprf.Mode.OPRF:
                        server = new OPRFServer(id, privateKey, cryptoProvider)
                        client = new OPRFClient(id, cryptoProvider)
                        break

                    case Oprf.Mode.VOPRF:
                        server = new VOPRFServer(id, privateKey, cryptoProvider)
                        client = new VOPRFClient(id, publicKey, cryptoProvider)
                        break
                    case Oprf.Mode.POPRF:
                        server = new POPRFServer(id, privateKey, cryptoProvider)
                        client = new POPRFClient(id, publicKey, cryptoProvider)
                        break
                }
            })

            it(`${id}`, async () => {
                // Client                                       Server
                // ====================================================
                // Client
                // blind, blindedElement = Blind(input)
                const input = new TextEncoder().encode('This is the client input')
                const [finData, evalReq] = await client.blind([input])
                //             evalReq
                //       ------------------>>
                //                                              Server
                //          evaluation = BlindEvaluate(evalReq, info*)
                const evaluation = await server.blindEvaluate(evalReq)
                //            evaluation
                //       <<------------------
                //
                // Client
                // output = Finalize(finData, evaluation, info*)
                //
                const output = await client.finalize(finData, evaluation)
                expect(output[0]).toHaveLength(Oprf.getOprfSize(id))

                if (evaluation.proof) {
                    await testBadProof(client, server, finData, evaluation)
                }

                const serverOutput = await server.evaluate(input)
                expect(output[0]).toStrictEqual(serverOutput)

                const success = await server.verifyFinalize(input, output[0])
                expect(success).toBe(true)

                expect(serdeClass(FinalizeData, finData, client.gg)).toBe(true)
                expect(serdeClass(EvaluationRequest, evalReq, client.gg)).toBe(true)
                expect(serdeClass(Evaluation, evaluation, server.constructDLEQParams())).toBe(true)
            })
        })
    })
})
