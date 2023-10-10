// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    derivePrivateKey,
    generatePublicKey,
    getSupportedSuites,
    type ModeID,
    Oprf,
    OPRFClient,
    OPRFServer,
    POPRFClient,
    POPRFServer,
    type SuiteID,
    VOPRFClient,
    VOPRFServer,
    DLEQProver
} from '../src/index.js'
import { describeGroupTests } from './describeGroupTests.js'

// Test vectors taken from reference implementation at https://github.com/cfrg/draft-irtf-cfrg-voprf
import allVectors from './testdata/allVectors_v20.json'
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

    blindEvaluate(
        ...r: Parameters<OPRFServer['blindEvaluate']>
    ): ReturnType<OPRFServer['blindEvaluate']> {
        return super.blindEvaluate(r[0], this.info)
    }

    async evaluate(input: Uint8Array): Promise<Uint8Array> {
        return super.evaluate(input, this.info)
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

describeGroupTests((g) => {
    // Test vectors from https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf
    // https://tools.ietf.org/html/draft-irtf-cfrg-voprf-11
    describe.each(allVectors)('test-vectors', (testVector: TestVector) => {
        const mode = testVector.mode as ModeID
        const txtMode = Object.entries(Oprf.Mode)[mode as number][0]

        const supported = getSupportedSuites(g)
        const id = testVector.identifier as SuiteID
        const describeOrSkip = supported.includes(id) ? describe : describe.skip

        describeOrSkip(`${txtMode}, ${id}`, () => {
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

            describe.each(testVector.vectors)('vec$#', (vi: SingleVector) => {
                it('protocol', async () => {
                    const group = Oprf.getGroup(id)

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
                        jest.spyOn(DLEQProver.prototype, 'randomScalar').mockResolvedValueOnce(
                            group.desScalar(fromHex(vi.Proof.r))
                        )
                    }

                    if (testVector.mode === Oprf.Mode.POPRF && vi.Info) {
                        const info = fromHex(vi.Info)
                        ;(server as wrapPOPRFServer).info = info
                        ;(client as wrapPOPRFClient).info = info
                    }

                    const input = fromHexList(vi.Input)
                    const [finData, evalReq] = await client.blind(input)
                    expect(toHexListClass(finData.blinds)).toEqual(vi.Blind)
                    expect(toHexListClass(evalReq.blinded)).toEqual(vi.BlindedElement)

                    const ev = await server.blindEvaluate(evalReq)
                    expect(toHexListClass(ev.evaluated)).toEqual(vi.EvaluationElement)
                    expect(ev.proof && toHexListClass([ev.proof])).toEqual(
                        vi.Proof && vi.Proof.proof
                    )

                    const output = await client.finalize(finData, ev)
                    expect(toHexListUint8Array(output)).toEqual(vi.Output)

                    const serverCheckOutput = zip(input, output).every(
                        async (inout) => await server.verifyFinalize(inout[0], inout[1])
                    )
                    expect(serverCheckOutput).toBe(true)
                })
            })
        })
    })
})
