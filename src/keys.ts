// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { Oprf, OprfID } from './oprf.js'
import { SerializedElt, SerializedScalar } from './group.js'
import { joinAll, to16bits } from './util.js'

export function getKeySizes(id: OprfID): { Nsk: number; Npk: number } {
    const { gg } = Oprf.params(id)
    return { Nsk: gg.size, Npk: 1 + gg.size }
}

export function validatePrivateKey(id: OprfID, privateKey: Uint8Array): boolean {
    try {
        const { gg } = Oprf.params(id),
            s = gg.deserializeScalar(new SerializedScalar(privateKey))
        return !s.equals(0)
    } catch (_) {
        return false
    }
}

export function validatePublicKey(id: OprfID, publicKey: Uint8Array): boolean {
    try {
        const { gg } = Oprf.params(id),
            P = gg.deserialize(new SerializedElt(publicKey))
        return !P.isIdentity
    } catch (_) {
        return false
    }
}

export async function randomPrivateKey(id: OprfID): Promise<Uint8Array> {
    const { gg } = Oprf.params(id),
        priv = await gg.randomScalar()
    return new Uint8Array(gg.serializeScalar(priv))
}

export async function derivePrivateKey(
    id: OprfID,
    seed: Uint8Array,
    info: Uint8Array
): Promise<Uint8Array> {
    const { gg } = Oprf.params(id),
        deriveInput = joinAll([seed, to16bits(info.length), info])
    let counter = 0,
        priv

    do {
        if (counter > 255) {
            throw new Error('DeriveKeyPairError')
        }
        const hashInput = joinAll([deriveInput, Uint8Array.from([counter])])
        priv = await gg.hashToScalar(hashInput, Oprf.getDeriveKeyPairDST(id))
        counter++
    } while (gg.isScalarZero(priv))

    return new Uint8Array(gg.serializeScalar(priv))
}

export function generatePublicKey(id: OprfID, privateKey: Uint8Array): Uint8Array {
    const { gg } = Oprf.params(id),
        priv = gg.deserializeScalar(new SerializedScalar(privateKey)),
        pub = gg.mulBase(priv)
    return new Uint8Array(gg.serialize(pub))
}

export async function generateKeyPair(
    id: OprfID
): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
    const privateKey = await randomPrivateKey(id),
        publicKey = generatePublicKey(id, privateKey)
    return { privateKey, publicKey }
}

export async function deriveKeyPair(
    id: OprfID,
    seed: Uint8Array,
    info: Uint8Array
): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
    const privateKey = await derivePrivateKey(id, seed, info),
        publicKey = generatePublicKey(id, privateKey)
    return { privateKey, publicKey }
}
