// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    derivePrivateKey,
    generatePublicKey,
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
import { zip } from '../src/util.js'
import { describeCryptoTests } from './describeCryptoTests.js'

// Test vectors taken from reference implementation at https://github.com/cfrg/draft-irtf-cfrg-voprf
import allVectors from './testdata/allVectors_v20.json'
import { jest } from '@jest/globals'
import { expectToBeDefined } from './util.js'

function fromHex(x: string): Uint8Array<ArrayBuffer> {
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

type SingleVector = {
    Batch: number
    Blind: string
    BlindedElement: string
    EvaluationElement: string
    Info?: string
    Input: string
    Output: string
    Proof?: {
        proof: string
        r: string
    }
}

type TestVector = {
    groupDST: string
    hash: string
    identifier: string
    keyInfo: string
    mode: number
    seed: string
    skSm: string
    vectors: SingleVector[]
}
describeCryptoTests(({ provider, supportedSuites: supported }) => {
    // Test vectors from https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf
    // https://tools.ietf.org/html/draft-irtf-cfrg-voprf-11
    describe.each(allVectors)('test-vectors', (testVector: TestVector) => {
        const mode = testVector.mode as ModeID
        const txtMode = Object.entries(Oprf.Mode)[mode as number][0]

        const id = testVector.identifier as SuiteID
        const index = supported.findIndex((v) => v[0] === id)
        const describeOrSkip = index >= 0 ? describe : describe.skip

        describeOrSkip(`${txtMode}, ${id}`, () => {
            let skSm: Uint8Array
            let server: OPRFServer | VOPRFServer | POPRFServer
            let client: OPRFClient | VOPRFClient | POPRFClient

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

            describe.each(testVector.vectors)('vec$#', (vi: SingleVector) => {
                it('protocol', async () => {
                    const suiteParams = supported[index | 0]
                    expectToBeDefined(suiteParams)

                    const group = provider.Group.get(suiteParams[1])

                    // Creates a mock for randomBlinder method to
                    // inject the blind value given by the test vector.
                    const scList = fromHexList(vi.Blind)
                    expect(scList.length).toBe(vi.Batch)

                    const rB = jest.spyOn(client, 'randomBlinder')
                    for (const sc of scList) {
                        rB.mockResolvedValueOnce(group.desScalar(sc))
                    }

                    // Creates a mock for DLEQProver.randomScalar method to
                    // inject the random value used to generate a DLEQProof.
                    if (vi.Proof) {
                        jest.spyOn(server['prover'], 'randomScalar').mockResolvedValueOnce(
                            group.desScalar(fromHex(vi.Proof.r))
                        )
                    }

                    let info: Uint8Array<ArrayBuffer> | undefined = undefined
                    if (testVector.mode === Oprf.Mode.POPRF) {
                        expectToBeDefined(vi.Info)
                        info = fromHex(vi.Info)
                    }

                    const input = fromHexList(vi.Input)
                    const [finData, evalReq] = await client.blind(input)
                    expect(toHexListClass(finData.blinds)).toEqual(vi.Blind)
                    expect(toHexListClass(evalReq.blinded)).toEqual(vi.BlindedElement)

                    const ev = await server.blindEvaluate(evalReq, info)
                    expect(toHexListClass(ev.evaluated)).toEqual(vi.EvaluationElement)
                    expect(ev.proof && toHexListClass([ev.proof])).toEqual(
                        vi.Proof && vi.Proof.proof
                    )

                    const output = await client.finalize(finData, ev, info)
                    expect(toHexListUint8Array(output)).toEqual(vi.Output)

                    const serverCheckOutput = await Promise.all(
                        zip(input, output).map((inout) =>
                            server.verifyFinalize(inout[0], inout[1], info)
                        )
                    )
                    serverCheckOutput.forEach((x) => {
                        expect(x).toBe(true)
                    })
                })
            })
        })
    })
})
