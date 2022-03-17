// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    Blind,
    ModeID,
    OPRFClient,
    OPRFServer,
    Oprf,
    SuiteID,
    derivePrivateKey
} from '../src/index.js'

import allVectors from './testdata/allVectors_v09.json'
import { jest } from '@jest/globals'

function fromHex(x: string): Uint8Array {
    return Uint8Array.from(Buffer.from(x, 'hex'))
}

function toHex(x: Uint8Array): string {
    return Buffer.from(x).toString('hex')
}

// Test vectors from https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf
// https://tools.ietf.org/html/draft-irtf-cfrg-voprf-06
describe.each(allVectors)('test-vectors', (testVector: typeof allVectors[number]) => {
    const mode = testVector.mode as ModeID
    const id = testVector.suiteID as SuiteID

    if (mode === Oprf.Mode.OPRF && Object.values(Oprf.Suite).includes(id)) {
        const txtMode = Object.entries(Oprf.Mode)[mode as number][0]
        const txtSuite = Object.entries(Oprf.Suite)[Object.values(Oprf.Suite).indexOf(id)][0]

        describe(`${txtMode}, ${txtSuite}`, () => {
            it('keygen', async () => {
                const seed = fromHex(testVector.seed)
                const info = fromHex(testVector.keyInfo)
                const skSm = await derivePrivateKey(mode, id, seed, info)
                expect(toHex(skSm)).toBe(testVector.skSm)
            })

            const server = new OPRFServer(id, fromHex(testVector.skSm))
            const client = new OPRFClient(id)
            const { vectors } = testVector

            server.supportsWebCryptoOPRF = false

            it.each(vectors)('vec$#', async (vi: typeof vectors[number]) => {
                // Creates a mock for OPRFClient.randomBlinder method to
                // inject the blind value given by the test vector.
                jest.spyOn(OPRFClient.prototype, 'randomBlinder').mockImplementationOnce(() => {
                    const blind = new Blind(fromHex(vi.Blind))
                    const gg = Oprf.getGroup(id)
                    const scalar = gg.deserializeScalar(blind)
                    return Promise.resolve({ scalar, blind })
                })

                const input = fromHex(vi.Input)
                const [finData, evalReq] = await client.blind(input)
                expect(toHex(finData.blind)).toEqual(vi.Blind)
                expect(toHex(evalReq.blinded)).toEqual(vi.BlindedElement)

                const evaluation = await server.evaluate(evalReq)
                expect(toHex(evaluation.element)).toEqual(vi.EvaluationElement)

                const output = await client.finalize(finData, evaluation)
                expect(toHex(output)).toEqual(vi.Output)

                const serverCheckOutput = await server.verifyFinalize(input, output)
                expect(serverCheckOutput).toBe(true)
            })
        })
    }
})
