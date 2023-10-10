// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { getOprfParams, type ModeID, Oprf, type SuiteID } from './oprf.js'
import { joinAll, toU16LenPrefix } from './util.js'
import { type Scalar } from './groupTypes.js'
import type { CryptoProvider } from './cryptoTypes.js'

// TODO:
function getGroup(suite: SuiteID, crypto: CryptoProvider) {
    return crypto.Group.fromID(getOprfParams(suite)[1])
}

export function getKeySizes(id: SuiteID, crypto: CryptoProvider): { Nsk: number; Npk: number } {
    const gg = getGroup(id, crypto)
    return { Nsk: gg.scalarSize(), Npk: gg.eltSize(true) }
}

export function validatePrivateKey(
    id: SuiteID,
    privateKey: Uint8Array,
    crypto: CryptoProvider
): boolean {
    try {
        const group = getGroup(id, crypto)
        const s = group.desScalar(privateKey)
        return !s.isZero()
    } catch (_) {
        return false
    }
}

export function validatePublicKey(
    id: SuiteID,
    publicKey: Uint8Array,
    crypto: CryptoProvider
): boolean {
    try {
        const group = getGroup(id, crypto)
        const P = group.desElt(publicKey)
        return !P.isIdentity()
    } catch (_) {
        return false
    }
}

export async function randomPrivateKey(id: SuiteID, crypto: CryptoProvider): Promise<Uint8Array> {
    let priv: Scalar
    do {
        const gg = getGroup(id, crypto)
        priv = await gg.randomScalar()
    } while (priv.isZero())

    return priv.serialize()
}

export async function derivePrivateKey(
    mode: ModeID,
    id: SuiteID,
    seed: Uint8Array,
    info: Uint8Array,
    crypto: CryptoProvider
): Promise<Uint8Array> {
    const gg = getGroup(id, crypto)
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

export function generatePublicKey(
    id: SuiteID,
    privateKey: Uint8Array,
    crypto: CryptoProvider
): Uint8Array {
    const gg = getGroup(id, crypto)
    const priv = gg.desScalar(privateKey)
    const pub = gg.mulGen(priv)
    return pub.serialize(true)
}

export async function generateKeyPair(
    id: SuiteID,
    crypto: CryptoProvider
): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
    const privateKey = await randomPrivateKey(id, crypto)
    const publicKey = generatePublicKey(id, privateKey, crypto)
    return { privateKey, publicKey }
}

export async function deriveKeyPair(
    mode: ModeID,
    id: SuiteID,
    seed: Uint8Array,
    info: Uint8Array,
    crypto: CryptoProvider
): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
    const privateKey = await derivePrivateKey(mode, id, seed, info, crypto)
    const publicKey = generatePublicKey(id, privateKey, crypto)
    return { privateKey, publicKey }
}
