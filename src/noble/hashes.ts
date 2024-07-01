// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { sha256 } from '@noble/hashes/sha256'
import { sha384, sha512 } from '@noble/hashes/sha512'
import type { Hash, CHash } from '@noble/hashes/utils'
import { wrapConstructor } from '@noble/hashes/utils'
import type { Keccak } from '@noble/hashes/sha3'
import { shake256 } from '@noble/hashes/sha3'
import type { HashID } from '../cryptoTypes.js'

export const shake256_512 = wrapConstructor<Hash<Keccak>>(() => shake256.create({ dkLen: 64 }))

const HASHES: Record<HashID, CHash> = {
    'SHA-256': sha256,
    'SHA-384': sha384,
    'SHA-512': sha512,
    SHAKE256: shake256_512
}

export function hashSync(hashID: HashID, input: Uint8Array) {
    if (!(hashID in HASHES)) {
        throw new Error(`Unknown hashID=${hashID}`)
    }
    const { [hashID]: fn } = HASHES
    return fn(input)
}
