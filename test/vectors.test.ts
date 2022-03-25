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
    POPRFClient,
    POPRFServer,
    Scalar,
    SuiteID,
    VOPRFClient,
    VOPRFServer,
    derivePrivateKey,
    generatePublicKey
} from '../src/index.js'

import allVectors from './testdata/allVectors_v09.json'
import { jest } from '@jest/globals'

function fromHex(x: string): Uint8Array {
    return Uint8Array.from(Buffer.from(x, 'hex'))
}

function toHex(x: Uint8Array): string {
    return Buffer.from(x).toString('hex')
}

class wrapPOPRFServer extends POPRFServer {
    info!: Uint8Array

    evaluate(...r: Parameters<OPRFServer['evaluate']>): ReturnType<OPRFServer['evaluate']> {
        return super.evaluate(r[0], this.info)
    }
    async fullEvaluate(input: Uint8Array): Promise<Uint8Array> {
        return super.fullEvaluate(input, this.info)
    }
    async verifyFinalize(input: Uint8Array, output: Uint8Array): Promise<boolean> {
        return super.verifyFinalize(input, output, this.info)
    }
}

class wrapPOPRFClient extends POPRFClient {
    info!: Uint8Array

    blind(input: Uint8Array): ReturnType<OPRFClient['blind']> {
        return super.blind(input)
    }
    finalize(...r: Parameters<OPRFClient['finalize']>): ReturnType<OPRFClient['finalize']> {
        return super.finalize(...r, this.info)
    }
}

// Test vectors from https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf
// https://tools.ietf.org/html/draft-irtf-cfrg-voprf-09
describe.each(allVectors)('test-vectors', (testVector: typeof allVectors[number]) => {
    const mode = testVector.mode as ModeID
    const id = testVector.suiteID as SuiteID

    if (Object.values(Oprf.Suite).includes(id)) {
        const txtMode = Object.entries(Oprf.Mode)[mode as number][0]
        const txtSuite = Object.entries(Oprf.Suite)[Object.values(Oprf.Suite).indexOf(id)][0]

        describe(`${txtMode}, ${txtSuite}`, () => {
            let skSm: Uint8Array
            let server: OPRFServer | VOPRFServer | wrapPOPRFServer
            let client: OPRFClient | VOPRFClient | wrapPOPRFClient

            beforeAll(async () => {
                const seed = fromHex(testVector.seed)
                const keyInfo = fromHex(testVector.keyInfo)
                skSm = await derivePrivateKey(mode, id, seed, keyInfo)
                const pkSm = generatePublicKey(id, skSm)
                switch (mode) {
                    case Oprf.Mode.OPRF:
                        server = new OPRFServer(id, skSm)
                        client = new OPRFClient(id)
                        break

                    case Oprf.Mode.VOPRF:
                        server = new VOPRFServer(id, skSm)
                        client = new VOPRFClient(id, pkSm)
                        break

                    case Oprf.Mode.POPRF:
                        server = new wrapPOPRFServer(id, skSm)
                        client = new wrapPOPRFClient(id, pkSm)
                        break
                }
            })

            it('keygen', () => {
                expect(toHex(skSm)).toBe(testVector.skSm)
            })

            const { vectors } = testVector

            describe.each(vectors)('vec$#', (vi: typeof vectors[number]) => {
                if (vi.Batch === 1) {
                    it('protocol', async () => {
                        // Creates a mock for randomBlinder method to
                        // inject the blind value given by the test vector.
                        for (const c of [OPRFClient, VOPRFClient, wrapPOPRFClient]) {
                            jest.spyOn(c.prototype, 'randomBlinder').mockImplementation(() => {
                                const blind = new Blind(fromHex(vi.Blind))
                                const scalar = Scalar.deserialize(Oprf.getGroup(id), blind)
                                return Promise.resolve({ scalar, blind })
                            })
                        }

                        if (testVector.mode === Oprf.Mode.POPRF) {
                            const info = fromHex((vi as any).Info as string) // eslint-disable-line @typescript-eslint/no-explicit-any
                            ;(server as wrapPOPRFServer).info = info
                            ;(client as wrapPOPRFClient).info = info
                        }

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
                }
            })
        })
    }
})
