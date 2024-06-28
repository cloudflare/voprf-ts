// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { type ModeID, Oprf, type SuiteID } from './oprf.js'
import { joinAll, toU16LenPrefix } from './util.js'
import type { Scalar } from './groupTypes.js'
import { type CryptoProviderArg, getSuiteGroup } from './cryptoImpl.js'

export function getKeySizes(id: SuiteID, ...arg: CryptoProviderArg): { Nsk: number; Npk: number } {
    const gg = getSuiteGroup(id, arg)
    return { Nsk: gg.scalarSize(), Npk: gg.eltSize(true) }
}

export function validatePrivateKey(
    id: SuiteID,
    privateKey: Uint8Array,
    ...arg: CryptoProviderArg
): boolean {
    try {
        const gg = getSuiteGroup(id, arg)
        const s = gg.desScalar(privateKey)
        return !s.isZero()
    } catch (_) {
        return false
    }
}

export function validatePublicKey(
    id: SuiteID,
    publicKey: Uint8Array,
    ...arg: CryptoProviderArg
): boolean {
    try {
        const gg = getSuiteGroup(id, arg)
        const P = gg.desElt(publicKey)
        return !P.isIdentity()
    } catch (_) {
        return false
    }
}

export async function randomPrivateKey(
    id: SuiteID,
    ...arg: CryptoProviderArg
): Promise<Uint8Array> {
    let priv: Scalar
    do {
        const gg = getSuiteGroup(id, arg)
        priv = await gg.randomScalar()
    } while (priv.isZero())

    return priv.serialize()
}

export async function derivePrivateKey(
    mode: ModeID,
    id: SuiteID,
    seed: Uint8Array,
    info: Uint8Array,
    ...arg: CryptoProviderArg
): Promise<Uint8Array> {
    const gg = getSuiteGroup(id, arg)
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
    ...arg: CryptoProviderArg
): Uint8Array {
    const gg = getSuiteGroup(id, arg)
    const priv = gg.desScalar(privateKey)
    const pub = gg.mulGen(priv)
    return pub.serialize(true)
}

export async function generateKeyPair(
    id: SuiteID,
    ...arg: CryptoProviderArg
): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
    const privateKey = await randomPrivateKey(id, ...arg)
    const publicKey = generatePublicKey(id, privateKey, ...arg)
    return { privateKey, publicKey }
}

export async function deriveKeyPair(
    mode: ModeID,
    id: SuiteID,
    seed: Uint8Array,
    info: Uint8Array,
    ...arg: CryptoProviderArg
): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
    const privateKey = await derivePrivateKey(mode, id, seed, info, ...arg)
    const publicKey = generatePublicKey(id, privateKey, ...arg)
    return { privateKey, publicKey }
}
