// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    type DLEQParams,
    type Elt,
    type Scalar,
    CryptoImpl,
    DLEQProof,
    DLEQProver
} from '../src/index.js'
import { describeCryptoTests } from './describeCryptoTests.js'
import { serdeClass } from './util.js'

describeCryptoTests((g) => {
    describe.each(g.supportedGroups)('DLEQ', (id) => {
        const groupName = id
        const gg = CryptoImpl.Group.fromID(id)
        const params: DLEQParams = {
            gg,
            hashID: 'SHA-256',
            dst: 'domain-sep'
        }
        const Peggy = new DLEQProver(params)

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
                expect(await proof.verify([P, kP], [Q, kQ])).toBe(true)
            })

            it(`prove-batch/${i}`, async () => {
                expect(await proofBatched.verify_batch([P, kP], list)).toBe(true)
            })

            it(`invalid-arguments/${i}`, async () => {
                expect(await proof.verify([kP, P], [Q, kQ])).toBe(false)
            })

            it(`invalid-proof/${i}`, async () => {
                expect(await proof.verify([kP, P], [Q, kQ])).toBe(false)
            })

            it(`bad-key/${i}`, async () => {
                const badKey = await gg.randomScalar()
                const badProof: DLEQProof = await Peggy.prove(badKey, [P, kP], [Q, kQ])
                expect(await badProof.verify([P, kP], [Q, kQ])).toBe(false)
            })

            it(`serde/${i}`, async () => {
                expect(serdeClass(DLEQProof, proof, params)).toBe(true)
                expect(serdeClass(DLEQProof, proofBatched, params)).toBe(true)
            })
        })
    })
})
