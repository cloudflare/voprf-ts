// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
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

import allVectors from './testdata/allVectors_v10.json'
import { jest } from '@jest/globals'
import { zip } from './util.js'

function fromHex(x: string): Uint8Array {
    return Uint8Array.from(Buffer.from(x, 'hex'))
}

function fromHexList(x: string): Uint8Array[] {
    return x.split(',').map((l) => fromHex(l))
}

function toHex(x: Uint8Array): string {
    return Buffer.from(x).toString('hex')
}

function toHexListUint8Array(x: Uint8Array[]): string {
    return x.map((xi) => toHex(xi)).join(',')
}

function toHexListClass(x: { serialize(): Uint8Array }[]): string {
    return toHexListUint8Array(x.map((xi) => xi.serialize()))
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

    blind(inputs: Uint8Array[]): ReturnType<OPRFClient['blind']> {
        return super.blind(inputs)
    }
    finalize(...r: Parameters<OPRFClient['finalize']>): ReturnType<OPRFClient['finalize']> {
        return super.finalize(...r, this.info)
    }
}

// Test vectors from https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf
// https://tools.ietf.org/html/draft-irtf-cfrg-voprf-10
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
                it('protocol', async () => {
                    // Creates a mock for randomBlinder method to
                    // inject the blind value given by the test vector.
                    for (const c of [OPRFClient, VOPRFClient, wrapPOPRFClient]) {
                        let i = 0
                        jest.spyOn(c.prototype, 'randomBlinder').mockImplementation(() => {
                            return Promise.resolve(
                                Scalar.deserialize(Oprf.getGroup(id), fromHexList(vi.Blind)[i++])
                            )
                        })
                    }

                    if (testVector.mode === Oprf.Mode.POPRF) {
                        const info = fromHex((vi as any).Info as string) // eslint-disable-line @typescript-eslint/no-explicit-any
                        ;(server as wrapPOPRFServer).info = info
                        ;(client as wrapPOPRFClient).info = info
                    }

                    const input = fromHexList(vi.Input)
                    const [finData, evalReq] = await client.blind(input)
                    expect(toHexListClass(finData.blinds)).toEqual(vi.Blind)
                    expect(toHexListClass(evalReq.blinded)).toEqual(vi.BlindedElement)

                    const ev = await server.evaluate(evalReq)
                    expect(toHexListClass(ev.evaluated)).toEqual(vi.EvaluationElement)

                    const output = await client.finalize(finData, ev)
                    expect(toHexListUint8Array(output)).toEqual(vi.Output)

                    const serverCheckOutput = zip(input, output).every(
                        async (inout) => await server.verifyFinalize(inout[0], inout[1])
                    )
                    expect(serverCheckOutput).toBe(true)
                })
            })
        })
    }
})
