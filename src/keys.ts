// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { ModeID, Oprf, SuiteID } from './oprf.js'
import { joinAll, toU16LenPrefix } from './util.js'
import { Scalar } from './groupTypes.js'

export function getKeySizes(id: SuiteID): { Nsk: number; Npk: number } {
    const gg = Oprf.getGroup(id)
    return { Nsk: gg.size, Npk: 1 + gg.size }
}

export function validatePrivateKey(id: SuiteID, privateKey: Uint8Array): boolean {
    try {
        const s = Oprf.getGroup(id).desScalar(privateKey)
        return !s.isZero()
    } catch (_) {
        return false
    }
}

export function validatePublicKey(id: SuiteID, publicKey: Uint8Array): boolean {
    try {
        const P = Oprf.getGroup(id).desElt(publicKey)
        return !P.isIdentity()
    } catch (_) {
        return false
    }
}

export async function randomPrivateKey(id: SuiteID): Promise<Uint8Array> {
    const gg = Oprf.getGroup(id)
    let priv: Scalar
    do {
        priv = await gg.randomScalar()
    } while (priv.isZero())

    return priv.serialize()
}

export async function derivePrivateKey(
    mode: ModeID,
    id: SuiteID,
    seed: Uint8Array,
    info: Uint8Array
): Promise<Uint8Array> {
    const gg = Oprf.getGroup(id)
    const deriveInput = joinAll([seed, ...toU16LenPrefix(info)])
    let counter = 0
    let priv: Scalar

    do {
        if (counter > 255) {
            throw new Error('DeriveKeyPairError')
        }
        const hashInput = joinAll([deriveInput, Uint8Array.from([counter])])
        priv = await gg.hashToScalar(hashInput, Oprf.getDST(mode, id, Oprf.LABELS.DeriveKeyPairDST))
        counter++
    } while (priv.isZero())

    return priv.serialize()
}

export function generatePublicKey(id: SuiteID, privateKey: Uint8Array): Uint8Array {
    const gg = Oprf.getGroup(id)
    const priv = gg.desScalar(privateKey)
    const pub = gg.mulGen(priv)
    return pub.serialize()
}

export async function generateKeyPair(
    id: SuiteID
): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
    const privateKey = await randomPrivateKey(id)
    const publicKey = generatePublicKey(id, privateKey)
    return { privateKey, publicKey }
}

export async function deriveKeyPair(
    mode: ModeID,
    id: SuiteID,
    seed: Uint8Array,
    info: Uint8Array
): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
    const privateKey = await derivePrivateKey(mode, id, seed, info)
    const publicKey = generatePublicKey(id, privateKey)
    return { privateKey, publicKey }
}
