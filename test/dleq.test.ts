// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    type DLEQParams,
    type Elt,
    type Scalar,
    DLEQProof,
    DLEQProver,
    Oprf,
    DLEQVerifier
} from '../src/index.js'
import { describeGroupTests } from './describeGroupTests.js'
import { serdeClass } from './util.js'

describeGroupTests((g) => {
    describe.each(g.supportedGroups)('DLEQ', (id) => {
        const groupName = id
        const gg = Oprf.Crypto.Group.fromID(id)
        const te = new TextEncoder()
        const params: DLEQParams = {
            group: gg,
            hash: Oprf.Crypto.hash,
            hashID: 'SHA-256',
            dst: te.encode('domain-sep')
        }
        const Peggy = new DLEQProver(params)
        const Victor = new DLEQVerifier(params)

        let k: Scalar
        let P: Elt
        let kP: Elt
        let Q: Elt
        let kQ: Elt
        let proof: DLEQProof
        let proofBatched: DLEQProof
        let list: Array<[Elt, Elt]>

        describe.each([...Array(5).keys()])(`${groupName}`, (i: number) => {
            beforeAll(async () => {
                k = await gg.randomScalar()
                P = gg.mulGen(await gg.randomScalar())
                kP = P.mul(k)
                Q = gg.mulGen(await gg.randomScalar())
                kQ = Q.mul(k)
                proof = await Peggy.prove(k, [P, kP], [Q, kQ])

                list = new Array<[Elt, Elt]>()
                for (let l = 0; l < 3; l++) {
                    const R = gg.mulGen(await gg.randomScalar())
                    const kR = R.mul(k)
                    list.push([R, kR])
                }
                proofBatched = await Peggy.prove_batch(k, [P, kP], list)
            })

            it(`prove-single/${i}`, async () => {
                expect(await Victor.verify([P, kP], [Q, kQ], proof)).toBe(true)
            })

            it(`prove-batch/${i}`, async () => {
                expect(await Victor.verify_batch([P, kP], list, proofBatched)).toBe(true)
            })

            it(`invalid-arguments/${i}`, async () => {
                expect(await Victor.verify([kP, P], [Q, kQ], proof)).toBe(false)
            })

            it(`invalid-proof/${i}`, async () => {
                expect(await Victor.verify([kP, P], [Q, kQ], proof)).toBe(false)
            })

            it(`bad-key/${i}`, async () => {
                const badKey = await gg.randomScalar()
                const badProof: DLEQProof = await Peggy.prove(badKey, [P, kP], [Q, kQ])
                expect(await Victor.verify([P, kP], [Q, kQ], badProof)).toBe(false)
            })

            it(`serde/${i}`, async () => {
                expect(serdeClass(DLEQProof, proof, gg)).toBe(true)
                expect(serdeClass(DLEQProof, proofBatched, gg)).toBe(true)
            })
        })
    })
})
