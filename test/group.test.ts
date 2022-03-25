// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { Elt, Group, Scalar } from '../src/index.js'

describe.each(Object.entries(Group.ID))('group', (groupName, id) => {
    const gg = new Group(id)

    describe(`${groupName}`, () => {
        it('serdeElement', async () => {
            const P = gg.mulGen(await gg.randomScalar())

            for (const compress of [true, false]) {
                const serP = P.serialize(compress)
                const Q = Elt.deserialize(gg, serP)
                expect(P.isEqual(Q)).toBe(true)
            }
        })

        it('serdeElementZero', () => {
            const Z = gg.identity()
            const serZ = Z.serialize()
            const Z1 = Elt.deserialize(gg, serZ)
            expect(Z.isEqual(Z1)).toBe(true)
        })

        it('serdeScalar', async () => {
            const k = await gg.randomScalar()
            const serK = k.serialize()
            const k1 = Scalar.deserialize(gg, serK)
            expect(k.isEqual(k1)).toBe(true)
        })

        it('serdeScalarZero', () => {
            const z = gg.newScalar()
            const serZ = z.serialize()
            const z1 = Scalar.deserialize(gg, serZ)
            expect(z.isEqual(z1)).toBe(true)
        })
    })
})
