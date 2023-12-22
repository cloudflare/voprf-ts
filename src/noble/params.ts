// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause
import * as p256 from '@noble/curves/p256'
import * as p384 from '@noble/curves/p384'
import * as p521 from '@noble/curves/p521'
import * as ed25519 from '@noble/curves/ed25519'
import * as ed448 from '@noble/curves/ed448'
import { hashToRistretto255 } from '@noble/curves/ed25519'
import { hashToDecaf448 } from '@noble/curves/ed448'
import { sha512 } from '@noble/hashes/sha512'

import { errBadGroup, GROUP, type GroupID } from '../groupTypes.js'
import type { GroupParams } from './types.js'

import { shortCurve } from './short.js'
import { edwardsCurve } from './edwards.js'
import { shake256_512 } from './hashes.js'

const GROUPS: Record<GroupID, GroupParams> = {
    [GROUP.P256]: shortCurve({
        curve: p256.p256,
        hashID: 'SHA-256',
        elementHash: p256.hashToCurve,
        securityBits: 128
    }),
    [GROUP.P384]: shortCurve({
        curve: p384.p384,
        hashID: 'SHA-384',
        elementHash: p384.hashToCurve,
        securityBits: 192
    }),
    [GROUP.P521]: shortCurve({
        curve: p521.p521,
        hashID: 'SHA-512',
        elementHash: p521.hashToCurve,
        securityBits: 256
    }),

    [GROUP.RISTRETTO255]: edwardsCurve({
        curve: ed25519.ed25519,
        hashID: 'SHA-512',
        scalarHash: { type: 'xmd' },
        element: {
            hash: hashToRistretto255,
            Point: ed25519.RistrettoPoint
        },
        hash: sha512
    }),
    [GROUP.DECAF448]: edwardsCurve({
        curve: ed448.ed448,
        hashID: 'SHAKE256',
        scalarHash: { type: 'xof', k: 448 },
        element: {
            hash: hashToDecaf448,
            Point: ed448.DecafPoint
        },
        hash: shake256_512
    })
}

export function getParams(gid: GroupID) {
    if (!Object.values(GROUP).includes(gid)) throw errBadGroup(gid)
    return GROUPS[`${gid}`]
}
