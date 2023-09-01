// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { describeGroupTests } from './describeGroupTests.js'
import { serdeClass } from './util.js'

describeGroupTests((Group) => {
    describe.each(Object.entries(Group.ID))('%s', (_groupName, id) => {
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

            expect(serdeClass(Group.Elt, Z, gg)).toBe(true)
        })

        it('serdeScalar', async () => {
            const k = await gg.randomScalar()

            expect(serdeClass(Group.Scalar, k, gg)).toBe(true)
        })

        it('serdeScalarZero', () => {
            const z = gg.newScalar()

            expect(serdeClass(Group.Scalar, z, gg)).toBe(true)
        })
    })
})
