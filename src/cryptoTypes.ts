// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { GroupCons } from './groupTypes.js'

export type HashID = 'SHA-512' | 'SHA-256' | 'SHA-384' | 'SHAKE256'

export interface CryptoProvider {
    Group: GroupCons
    hash(hashID: HashID, input: Uint8Array): Promise<Uint8Array>
}
