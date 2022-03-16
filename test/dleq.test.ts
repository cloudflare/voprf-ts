// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { DLEQParams, DLEQProof, DLEQProver, Elt, Group, GroupID, Scalar } from '../src/index.js'

describe.each([GroupID.P256, GroupID.P384, GroupID.P521])('DLEQ', (id: GroupID) => {
    const gg = new Group(id)
    const params: DLEQParams = { gg, hash: 'SHA-256', dst: 'domain-sep' }
    const Peggy = new DLEQProver(params)

    let k: Scalar
    let P: Elt
    let kP: Elt
    let Q: Elt
    let kQ: Elt
    let proof: DLEQProof
    let proofBatched: DLEQProof
    let list: Array<[Elt, Elt]>

    describe.each([...Array(5).keys()])(`${gg.id}`, (i: number) => {
        beforeAll(async () => {
            k = await gg.randomScalar()
            P = gg.mulBase(await gg.randomScalar())
            kP = Group.mul(k, P)
            Q = gg.mulBase(await gg.randomScalar())
            kQ = Group.mul(k, Q)
            proof = await Peggy.prove(k, [P, kP], [Q, kQ])

            list = new Array<[Elt, Elt]>()
            for (let l = 0; l < 3; l++) {
                const c = gg.mulBase(await gg.randomScalar())
                const d = Group.mul(k, c)
                list.push([c, d])
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
    })
})
