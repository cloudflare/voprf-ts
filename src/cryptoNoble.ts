// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { GroupNb } from './noble/group.js'
import type { CryptoProvider, HashID } from './cryptoTypes.js'
import { hashSync } from './noble/hashes.js'

export const CryptoNoble: CryptoProvider = {
    id: 'noble',
    Group: GroupNb,
    hash(hashID: HashID, input: Uint8Array): Promise<Uint8Array> {
        return Promise.resolve(hashSync(hashID, input))
    }
}
