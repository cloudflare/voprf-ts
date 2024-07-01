// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    type CryptoProvider,
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
    type SuiteID,
    VOPRFClient,
    VOPRFServer
} from '../src/index.js'
import { describeCryptoTests } from './describeCryptoTests.js'

import { serdeClass } from './util.js'

async function testBadProof(
    client: OPRFClient,
    finData: FinalizeData,
    evaluation: Evaluation,
    crypto: CryptoProvider,
    suiteID: SuiteID
) {
    if (!evaluation.proof) throw new Error('no evaluation exists')

    const badEval = Evaluation.deserialize(suiteID, evaluation.serialize(), crypto)

    Object.assign(badEval, { proof: { s: evaluation.proof.c, c: evaluation.proof.c } })
    await expect(client.finalize(finData, badEval)).rejects.toThrow(/proof failed/)
}

describeCryptoTests(({ provider, supportedSuites }) => {
    describe.each(Object.entries(Oprf.Mode))('protocol', (modeName, mode) => {
        describe.each(supportedSuites)(`mode-${modeName}`, (id) => {
            let server: OPRFServer | VOPRFServer | POPRFServer
            let client: OPRFClient | VOPRFClient | POPRFClient

            beforeAll(async () => {
                const privateKey = await randomPrivateKey(id, provider)
                const publicKey = generatePublicKey(id, privateKey, provider)
                switch (mode) {
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
            })

            it(`id-${id}`, async () => {
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
                    await testBadProof(client, finData, evaluation, provider, id)
                }

                const serverOutput = await server.evaluate(input)
                expect(output).toStrictEqual(serverOutput)

                const success = await server.verifyFinalize(input, output)
                expect(success).toBe(true)

                expect(serdeClass(FinalizeData, finData, id, provider)).toBe(true)
                expect(serdeClass(EvaluationRequest, evalReq, id, provider)).toBe(true)
                expect(serdeClass(Evaluation, evaluation, id, provider)).toBe(true)
            })
        })
    })
})
