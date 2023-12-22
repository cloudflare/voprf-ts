// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { CryptoProviderArg } from '../src/cryptoImpl.js'

export function serdeClass<
    U,
    K extends {
        deserialize: (u: U, b: Uint8Array, ...arg: CryptoProviderArg) => T
    },
    T extends {
        serialize: () => Uint8Array
        isEqual: (t: T) => boolean
    }
>(k: K, t: T, u: U, ...arg: CryptoProviderArg): boolean {
    const ser = t.serialize()
    const deser = k.deserialize(u, ser, ...arg)
    return t.isEqual(deser)
}

export function serdesEquals<
    T extends {
        serialize: () => Uint8Array
        isEqual: (t: T) => boolean
    }
>(
    deserializer: {
        deserialize(b: Uint8Array): T
    },
    t: T
): boolean {
    const ser = t.serialize()
    const deser = deserializer.deserialize(ser)
    return t.isEqual(deser)
}

export function zip<T>(x: T[], y: T[]): Array<[T, T]> {
    return x.map<[T, T]>((xi, i) => [xi, y[i as number]])
}
