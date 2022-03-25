// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { Elt, Group, Scalar } from '../src/index.js'

import { serdeClass } from './util.js'

describe.each(Object.entries(Group.ID))('%s', (_groupName, id) => {
    const gg = new Group(id)

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

        expect(serdeClass(Elt, Z, gg)).toBe(true)
    })

    it('serdeScalar', async () => {
        const k = await gg.randomScalar()

        expect(serdeClass(Scalar, k, gg)).toBe(true)
    })

    it('serdeScalarZero', () => {
        const z = gg.newScalar()

        expect(serdeClass(Scalar, z, gg)).toBe(true)
    })
})
