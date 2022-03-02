// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    Oprf,
    OprfID,
    deriveKeyPair,
    generateKeyPair,
    getKeySizes,
    validatePrivateKey,
    validatePublicKey
} from '../src/index.js'

describe.each([OprfID.OPRF_P256_SHA256, OprfID.OPRF_P384_SHA384, OprfID.OPRF_P521_SHA512])(
    'oprf-keys',
    (id: OprfID) => {
        describe(`${OprfID[id as number]}`, () => {
            const { Nsk, Npk } = getKeySizes(id)
            const { gg } = Oprf.params(id)

            it('getKeySizes', () => {
                expect(Nsk).toBe(Npk - 1)
            })

            it('zeroPrivateKey', () => {
                const zeroKeyBytes = new Uint8Array(Nsk)
                const ret = validatePrivateKey(id, zeroKeyBytes)
                expect(ret).toBe(false)
            })

            it('orderPrivateKey', () => {
                const orderPk = gg.serializeScalar(gg.order())
                const ret = validatePrivateKey(id, orderPk)
                expect(ret).toBe(false)
            })

            it('onesPrivateKey', () => {
                const onesKeyBytes = new Uint8Array(Nsk).fill(0xff)
                const ret = validatePrivateKey(id, onesKeyBytes)
                expect(ret).toBe(false)
            })

            it('identityPublicKey', () => {
                const identityKeyBytes = gg.serialize(gg.identity())
                const ret = validatePublicKey(id, identityKeyBytes)
                expect(ret).toBe(false)
            })

            it('onesPublicKey', () => {
                const onesKeyBytes = new Uint8Array(Npk).fill(0xff)
                const ret = validatePublicKey(id, onesKeyBytes)
                expect(ret).toBe(false)
            })

            it('generateKeyPair', async () => {
                for (let i = 0; i < 64; i++) {
                    const keys = await generateKeyPair(id) // eslint-disable-line no-await-in-loop
                    const sk = validatePrivateKey(id, keys.privateKey)
                    const pk = validatePublicKey(id, keys.publicKey)
                    expect(sk).toBe(true)
                    expect(pk).toBe(true)
                }
            })

            it('deriveKeyPair', async () => {
                const info = new TextEncoder().encode('info used for derivation')
                for (let i = 0; i < 64; i++) {
                    const seed = crypto.getRandomValues(new Uint8Array(Nsk))
                    const keys = await deriveKeyPair(id, seed, info) // eslint-disable-line no-await-in-loop
                    const sk = validatePrivateKey(id, keys.privateKey)
                    const pk = validatePublicKey(id, keys.publicKey)
                    expect(sk).toBe(true)
                    expect(pk).toBe(true)
                }
            })
        })
    }
)
