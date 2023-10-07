// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    Evaluation,
    EvaluationRequest,
    FinalizeData,
    generatePublicKey,
    getSupportedSuites,
    Oprf,
    OPRFClient,
    OPRFServer,
    POPRFClient,
    POPRFServer,
    randomPrivateKey,
    VOPRFClient,
    VOPRFServer,
    type SuiteID
} from '../src/index.js'

import { describeGroupTests } from './describeGroupTests.js'
import { serdeClass } from './util.js'

async function testBadProof(
    id: SuiteID,
    client: OPRFClient,
    finData: FinalizeData,
    evaluation: Evaluation
) {
    const badEval = Evaluation.deserialize(id, evaluation.serialize())
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    Object.assign(badEval.proof!, { s: evaluation.proof!.c })
    await expect(client.finalize(finData, badEval)).rejects.toThrow(/proof failed/)
}

describeGroupTests((g) => {
    describe.each(Object.entries(Oprf.Mode))('protocol', (modeName, mode) => {
        describe.each(getSupportedSuites(g))(`${modeName}`, (id) => {
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
                const [output] = await client.finalize(finData, evaluation)
                expect(output).toHaveLength(Oprf.getOprfSize(id))

                if (evaluation.proof) {
                    await testBadProof(id, client, finData, evaluation)
                }

                const serverOutput = await server.evaluate(input)
                expect(output).toStrictEqual(serverOutput)

                const success = await server.verifyFinalize(input, output)
                expect(success).toBe(true)

                expect(serdeClass(FinalizeData, finData, id)).toBe(true)
                expect(serdeClass(EvaluationRequest, evalReq, id)).toBe(true)
                expect(serdeClass(Evaluation, evaluation, id)).toBe(true)
            })
        })
    })
})
