// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    derivePrivateKey,
    generatePublicKey,
    getOprfParams,
    type ModeID,
    Oprf,
    OPRFClient,
    OPRFServer,
    POPRFClient,
    POPRFServer,
    type SuiteID,
    VOPRFClient,
    VOPRFServer
} from '../src/index.js'
import { describeCryptoTests } from './describeCryptoTests.js'

// Test vectors taken from reference implementation at https://github.com/cfrg/draft-irtf-cfrg-voprf
import allVectors from './testdata/allVectors_v20.json'
import { jest } from '@jest/globals'
import { zip } from './util.js'
import type { Client, Server } from '../src/facade/types.js'

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

describeCryptoTests(({ provider, supportedSuites: supported }) => {
    // Test vectors from https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf
    // https://tools.ietf.org/html/draft-irtf-cfrg-voprf-11
    describe.each(allVectors)('test-vectors', (testVector: (typeof allVectors)[number]) => {
        const mode = testVector.mode as ModeID
        const txtMode = Object.entries(Oprf.Mode)[mode as number][0]

        const id = testVector.identifier as SuiteID
        const describeOrSkip = supported.includes(id) ? describe : describe.skip

        describeOrSkip(`${txtMode}, ${id}`, () => {
            let skSm: Uint8Array
            let server: Server
            let client: Client

            beforeAll(async () => {
                const seed = fromHex(testVector.seed)
                const keyInfo = fromHex(testVector.keyInfo)
                skSm = await derivePrivateKey(mode, id, seed, keyInfo, provider)
                const pkSm = generatePublicKey(id, skSm, provider)
                switch (mode) {
                    case Oprf.Mode.OPRF:
                        server = new OPRFServer(id, skSm, provider)
                        client = new OPRFClient(id, provider)
                        break

                    case Oprf.Mode.VOPRF:
                        server = new VOPRFServer(id, skSm, provider)
                        client = new VOPRFClient(id, pkSm, provider)
                        break

                    case Oprf.Mode.POPRF:
                        server = new POPRFServer(id, skSm, provider)
                        client = new POPRFClient(id, pkSm, provider)
                        break
                }
            })

            it('keygen', () => {
                expect(toHex(skSm)).toBe(testVector.skSm)
            })

            const { vectors } = testVector

            describe.each(vectors)('vec$#', (vi: (typeof vectors)[number]) => {
                it('protocol', async () => {
                    // Creates a mock for randomBlinder method to
                    // inject the blind value given by the test vector.
                    for (const c of [OPRFClient, VOPRFClient, POPRFClient]) {
                        let i = 0
                        jest.spyOn(c.prototype, 'randomBlinder').mockImplementation(() => {
                            const group = provider.Group.fromID(getOprfParams(id)[1])
                            return Promise.resolve(group.desScalar(fromHexList(vi.Blind)[i++]))
                        })
                    }

                    // Server/Client types handle this fine :) because `info` is optional
                    let info: Uint8Array | undefined = undefined
                    if (testVector.mode === Oprf.Mode.POPRF) {
                        info = fromHex((vi as { Info: string }).Info)
                    }

                    const input = fromHexList(vi.Input)
                    const [finData, evalReq] = await client.blind(input)
                    expect(toHexListClass(finData.blinds)).toEqual(vi.Blind)
                    expect(toHexListClass(evalReq.blinded)).toEqual(vi.BlindedElement)

                    const ev = await server.blindEvaluate(evalReq, info)
                    expect(toHexListClass(ev.evaluated)).toEqual(vi.EvaluationElement)

                    const output = await client.finalize(finData, ev, info)
                    expect(toHexListUint8Array(output)).toEqual(vi.Output)

                    const serverCheckOutput = zip(input, output).every(
                        async (inout) => await server.verifyFinalize(inout[0], inout[1], info)
                    )
                    expect(serverCheckOutput).toBe(true)
                })
            })
        })
    })
})
