// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { ProjPointType } from '@noble/curves/abstract/weierstrass'
import type { Elt } from '../groupTypes.js'
import { ScalarNb } from './scalar.js'
import type { Point, PointConstructor } from './types.js'
import type { GroupNb } from './group.js'
import { compat, errDeserialization } from '../util.js'

export class EltNb implements Elt {
    Point: PointConstructor

    private constructor(
        public readonly g: GroupNb,
        private readonly p: Point
    ) {
        this.Point = g.params.element.Point
    }

    static create(g: GroupNb): EltNb {
        return new EltNb(g, g.params.element.Point.ZERO)
    }

    static gen(g: GroupNb): EltNb {
        return new EltNb(g, g.params.element.Point.BASE)
    }

    isIdentity(): boolean {
        return this.p.equals(this.Point.ZERO)
    }

    isEqual(a: EltNb): boolean {
        compat(this, a)
        return this.p.equals(a.p)
    }

    neg(): EltNb {
        if (typeof this.p.negate === 'undefined') {
            // https://github.com/paulmillr/noble-curves/issues/84
            throw new Error(`Point doesn't implement negate: ${this.Point}`)
        } else {
            return new EltNb(this.g, this.p.negate())
        }
    }

    add(a: EltNb): EltNb {
        compat(this, a)
        return new EltNb(this.g, this.p.add(a.p))
    }

    mul(s: ScalarNb): EltNb {
        compat(this, s)
        return new EltNb(this.g, this.p.multiply(s.k))
    }

    mul2(k1: ScalarNb, a: EltNb, k2: ScalarNb): EltNb {
        compat(this, k1)
        compat(this, k2)
        compat(this, a)
        if (this.p.multiplyAndAddUnsafe) {
            const zero = this.Point.ZERO
            const el = this.p.multiplyAndAddUnsafe(a.p, k1.k, k2.k) ?? zero
            return new EltNb(this.g, el)
        } else {
            // Manually perform k1 * this.p + k2 * a.p
            const term1 = this.p.multiply(k1.k)
            const term2 = a.p.multiply(k2.k)
            const sum = term1.add(term2)
            return new EltNb(this.g, sum)
        }
    }

    serialize(compressed = true): Uint8Array {
        if (!this.g.params.isEdwards && this.isIdentity()) {
            return Uint8Array.from([0])
        }
        return this.p.toRawBytes(compressed)
    }

    // size returns the number of bytes of a non-zero element in compressed or uncompressed form.
    static size(g: GroupNb, compressed = true): number {
        const size = g.params.element.size
        return compressed ? size.compressed : size.standard
    }

    private static deser(g: GroupNb, bytes: Uint8Array): EltNb {
        const point = g.params.element.Point.fromHex(bytes)
        point.assertValidity?.()
        return new EltNb(g, point)
    }

    // Deserializes an element, handles both compressed and uncompressed forms.
    static deserialize(g: GroupNb, bytes: Uint8Array): EltNb {
        const {
            element: { size },
            isEdwards
        } = g.params

        const len = bytes.length
        const tag = bytes[0]

        switch (true) {
            case isEdwards && len === size.standard:
                return EltNb.deser(g, bytes)
            case isEdwards && len !== size.standard:
                throw errDeserialization(EltNb)
            case len === 1 && tag === 0x0:
                return g.identity() as EltNb
            case len === size.compressed && (tag === 0x02 || tag === 0x03):
            case len === size.standard && tag === 0x04:
                return EltNb.deser(g, bytes)
            default:
                throw errDeserialization(EltNb)
        }
    }

    static hash(g: GroupNb, msg: Uint8Array, dst: Uint8Array): EltNb {
        const h2c = g.params.element.hash
        const p = h2c(msg, { DST: dst }) as ProjPointType<bigint>
        return new EltNb(g, p as Point)
    }
}
