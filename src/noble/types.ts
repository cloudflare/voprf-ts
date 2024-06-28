// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { Field } from '@noble/curves/abstract/modular'
import type { CHash } from '@noble/hashes/utils'
import type * as p256 from '@noble/curves/p256'
import type * as ed25519 from '@noble/curves/ed25519'
import type * as ed448 from '@noble/curves/ed448'
import type { Hex } from '@noble/curves/abstract/utils'

import type { HashID } from '../cryptoTypes.js'

export type PrimeField = ReturnType<typeof Field>

export type HashToPointFunc =
    | typeof p256.hashToCurve
    | typeof ed25519.hashToRistretto255
    | typeof ed448.hashToDecaf448

export type ScalarHash =
    | { type: 'hash_to_field'; params: { k: number; p: bigint; expand: 'xmd' } }
    | { type: 'xmd' }
    | { type: 'xof'; k: number }

export interface ElementSize {
    // short: TAG_BYTE:X_BYTES
    // edwards: Y_BYTES
    compressed: number
    // short: TAG_BYTE:X_BYTES:Y_BYTES
    // edwards: Y_BYTES
    standard: number
}

export interface Element {
    Point: PointConstructor
    hash: HashToPointFunc
    size: ElementSize
}

export type ElementSpec = Pick<Element, 'Point' | 'hash'>

export interface GroupParams {
    isEdwards: boolean

    scalar: {
        field: PrimeField
        size: number
        hash: ScalarHash
    }

    element: Element

    hash: {
        id: HashID
        size: number
        fn: CHash
    }
}

// ed448.DecafPoint and ed25519.RistrettoPoint lack these methods so they are optional.
export interface PointOptionals {
    // So far, this method is not used by voprf-ts
    negate?(): Point

    // Will simply use add and multiply methods if this is not implemented
    multiplyAndAddUnsafe?(p: Point, k: bigint, k2: bigint): Point | null

    // ed448.DecafPoint and ed25519.RistrettoPoint fromHex methods both throw without any extra
    // step needed. If this "feature" is detected it will be used.
    assertValidity?: () => void
}

export interface Point extends PointOptionals {
    add(p: Point): Point

    equals(p: Point): boolean

    multiply(k: bigint): Point

    toRawBytes(compressed: boolean): Uint8Array
}

export interface PointConstructor {
    ZERO: Point
    BASE: Point

    fromHex(hex: Hex): Point
}
