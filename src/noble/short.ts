// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { Field } from '@noble/curves/abstract/modular'
import type { CurveFn } from '@noble/curves/abstract/weierstrass'
import type { GroupParams, HashToPointFunc, PointConstructor } from './types.js'
import type { HashID } from '../cryptoTypes.js'

export interface MakeShortParamsArgs {
    curve: CurveFn
    hashID: HashID
    elementHash: HashToPointFunc
    securityBits: number
}

export function shortCurve({
    hashID,
    curve,
    elementHash,
    securityBits
}: MakeShortParamsArgs): GroupParams {
    const scalarField = Field(curve.CURVE.n)
    const Point = curve.ProjectivePoint as PointConstructor
    const elementFieldSize = curve.CURVE.Fp.BYTES

    return {
        isEdwards: false,

        scalar: {
            field: scalarField,
            size: scalarField.BYTES,
            hash: {
                type: 'hash_to_field',
                params: { p: curve.CURVE.n, k: securityBits, expand: 'xmd' }
            }
        },

        element: {
            Point,
            hash: elementHash,
            size: {
                compressed: elementFieldSize + 1,
                standard: elementFieldSize * 2 + 1
            }
        },

        hash: {
            id: hashID,
            fn: curve.CURVE.hash,
            size: curve.CURVE.hash.outputLen
        }
    }
}
