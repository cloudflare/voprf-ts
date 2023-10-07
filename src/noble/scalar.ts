// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    expand_message_xmd,
    expand_message_xof,
    hash_to_field
} from '@noble/curves/abstract/hash-to-curve'

import type { Scalar } from '../groupTypes.js'
import { checkSize, compat, errDeserialization } from '../util.js'

import type { PrimeField } from './types.js'

// Avoid circular dependency by using import type
import type { GroupNb } from './group.js'

export class ScalarNb implements Scalar {
    private readonly field: PrimeField
    public readonly k: bigint

    private constructor(
        public readonly g: GroupNb,
        k: bigint
    ) {
        this.field = this.g.params.scalar.field
        this.k = this.field.create(k)
    }

    static create(g: GroupNb): ScalarNb {
        return new ScalarNb(g, BigInt(0))
    }

    isEqual(s: ScalarNb): boolean {
        compat(this, s)
        return this.k === s.k
    }

    isZero(): boolean {
        return this.k === BigInt(0)
    }

    add(s: ScalarNb): ScalarNb {
        compat(this, s)
        return new ScalarNb(this.g, this.field.add(this.k, s.k))
    }

    sub(s: ScalarNb): ScalarNb {
        compat(this, s)
        return new ScalarNb(this.g, this.field.sub(this.k, s.k))
    }

    mul(s: ScalarNb): ScalarNb {
        compat(this, s)
        return new ScalarNb(this.g, this.field.mul(this.k, s.k))
    }

    inv(): ScalarNb {
        return new ScalarNb(this.g, this.field.inv(this.k))
    }

    serialize(): Uint8Array {
        return this.field.toBytes(this.k)
    }

    static size(g: GroupNb): number {
        return g.params.scalar.size
    }

    static deserialize(g: GroupNb, bytes: Uint8Array): ScalarNb {
        checkSize(bytes, ScalarNb, g)
        const array = bytes.subarray(0, g.params.scalar.size)
        const k = g.bytesToNumber(array)
        if (k >= g.params.scalar.field.ORDER) {
            throw errDeserialization(ScalarNb)
        }
        return new ScalarNb(g, k)
    }

    static hash(g: GroupNb, msg: Uint8Array, dst: Uint8Array): ScalarNb {
        const { scalar, hash } = g.params

        if (scalar.hash.type === 'hash_to_field') {
            const [[k]] = hash_to_field(msg, 1, {
                ...{ hash: hash.fn },
                ...scalar.hash.params,
                DST: dst,
                m: 1
            })
            return new ScalarNb(g, k)
        } else {
            const uniform =
                scalar.hash.type === 'xmd'
                    ? expand_message_xmd(msg, dst, hash.size, hash.fn)
                    : expand_message_xof(msg, dst, hash.size, scalar.hash.k, hash.fn)
            const k1 = scalar.field.create(g.bytesToNumber(uniform))
            return new ScalarNb(g, k1)
        }
    }
}
