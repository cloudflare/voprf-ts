// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { CryptoProvider, HashID } from './cryptoTypes.js'
import { GroupConsSjcl } from './groupSjcl.js'

export const CryptoSjcl: CryptoProvider = {
    Group: GroupConsSjcl,
    async hash(hashID: HashID, input: Uint8Array): Promise<Uint8Array> {
        return new Uint8Array(await crypto.subtle.digest(hashID, input))
    }
}
