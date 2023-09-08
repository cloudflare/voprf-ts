// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import * as p256 from '@noble/curves/p256'
import * as p384 from '@noble/curves/p384'
import * as p521 from '@noble/curves/p521'
import * as ed25519 from '@noble/curves/ed25519'
import { hashToRistretto255 } from '@noble/curves/ed25519'
import * as ed448 from '@noble/curves/ed448'
import { hashToDecaf448 } from '@noble/curves/ed448'

import { errBadGroup, GroupID, Groups } from '../groupTypes.js'
import { GroupParams } from './types.js'
import { makeShortParams } from './short.js'
import { makeEdParams } from './edwards.js'
import { shake256_512 } from './hashes.js'

const GROUPS: Record<GroupID, GroupParams> = {
    [Groups.P256]: makeShortParams({
        curve: p256.p256,
        hashID: 'SHA-256',
        elementHash: p256.hashToCurve,
        securityBits: 128
    }),
    [Groups.P384]: makeShortParams({
        curve: p384.p384,
        hashID: 'SHA-384',
        elementHash: p384.hashToCurve,
        securityBits: 192
    }),
    [Groups.P521]: makeShortParams({
        curve: p521.p521,
        hashID: 'SHA-512',
        elementHash: p521.hashToCurve,
        securityBits: 256
    }),

    [Groups.RISTRETTO255]: makeEdParams({
        curve: ed25519.ed25519,
        hashID: 'SHA-512',
        scalarHash: { type: 'xmd' },
        element: {
            hash: hashToRistretto255,
            Point: ed25519.RistrettoPoint
        }
    }),
    [Groups.DECAF448]: makeEdParams({
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
    if (!Object.values(Groups).includes(gid)) throw errBadGroup(gid)
    // eslint-disable-next-line security/detect-object-injection
    return GROUPS[gid]
}
