// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { describeGroupTests } from './describeGroupTests.js'
import { serdesEquals } from './util.js'

describeGroupTests((Group) => {
    describe.each(Group.supportedGroups)('%s', (id) => {
        const gg = Group.fromID(id)

        it('serdeElement', async () => {
            const P = gg.mulGen(await gg.randomScalar())

            for (const compress of [true, false]) {
                const serP = P.serialize(compress)
                const Q = gg.desElt(serP)
                expect(P.isEqual(Q)).toBe(true)
            }
        })

        it('serdeElementZero', () => {
            const Z = gg.identity()
            expect(serdesEquals(gg.eltDes, Z)).toBe(true)
        })

        it('serdeScalar', async () => {
            const k = await gg.randomScalar()
            expect(serdesEquals(gg.scalarDes, k)).toBe(true)
        })

        it('serdeScalarZero', () => {
            const z = gg.newScalar()
            expect(serdesEquals(gg.scalarDes, z)).toBe(true)
        })
    })
})
