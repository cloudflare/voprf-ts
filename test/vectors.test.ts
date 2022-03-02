// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { Blind, OPRFClient, OPRFServer, Oprf, OprfID, derivePrivateKey } from '../src/index.js'

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
    const oprfID = testVector.suiteID
    if (testVector.mode === Oprf.mode && oprfID in OprfID) {
        describe(`${testVector.suiteName}/Mode${testVector.mode}`, () => {
            it('keygen', async () => {
                const seed = fromHex(testVector.seed)
                const info = fromHex(testVector.keyInfo)
                const skSm = await derivePrivateKey(oprfID, seed, info)
                expect(toHex(skSm)).toBe(testVector.skSm)
            })

            const server = new OPRFServer(oprfID, fromHex(testVector.skSm))
            const client = new OPRFClient(oprfID)
            const { vectors } = testVector

            server.supportsWebCryptoOPRF = false

            it.each(vectors)('vec$#', async (vi: typeof vectors[number]) => {
                // Creates a mock for OPRFClient.randomBlinder method to
                // inject the blind value given by the test vector.
                jest.spyOn(OPRFClient.prototype, 'randomBlinder').mockImplementationOnce(() => {
                    const blind = new Blind(fromHex(vi.Blind))
                    const { gg } = Oprf.params(oprfID)
                    const scalar = gg.deserializeScalar(blind)
                    return Promise.resolve({ scalar, blind })
                })

                const input = fromHex(vi.Input)
                const { blind, blindedElement } = await client.blind(input)
                expect(toHex(blind)).toEqual(vi.Blind)
                expect(toHex(blindedElement)).toEqual(vi.BlindedElement)

                const evaluation = await server.evaluate(blindedElement)
                expect(toHex(evaluation)).toEqual(vi.EvaluationElement)

                const output = await client.finalize(input, blind, evaluation)
                expect(toHex(output)).toEqual(vi.Output)

                const serverCheckOutput = await server.verifyFinalize(input, output)
                expect(serverCheckOutput).toBe(true)
            })
        })
    }
})
