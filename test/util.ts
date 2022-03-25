// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

export function serdeClass<
    U,
    K extends {
        deserialize: (u: U, b: Uint8Array) => T
    },
    T extends {
        serialize: () => Uint8Array
        isEqual: (t: T) => boolean
    }
>(k: K, t: T, u: U): boolean {
    const ser = t.serialize()
    const deser = k.deserialize(u, ser)
    return t.isEqual(deser)
}
