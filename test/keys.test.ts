// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    deriveKeyPair,
    generateKeyPair,
    getKeySizes,
    getOprfParams,
    Oprf,
    validatePrivateKey,
    validatePublicKey
} from '../src/index.js'
import { describeCryptoTests } from './describeCryptoTests.js'

describeCryptoTests(({ provider, supportedSuites }) => {
    describe.each(supportedSuites)('oprf-keys', (id) => {
        describe(`${id}`, () => {
            const { Nsk, Npk } = getKeySizes(id, provider)
            const gg = provider.Group.fromID(getOprfParams(id)[1])

            it('getKeySizes', () => {
                expect(Nsk).toBe(gg.scalarSize())
                expect(Npk).toBe(gg.eltSize(true))
            })

            it('zeroPrivateKey', () => {
                const zeroKeyBytes = new Uint8Array(Nsk)
                const ret = validatePrivateKey(id, zeroKeyBytes, provider)
                expect(ret).toBe(false)
            })

            it('badPrivateKey', () => {
                const bad = new Uint8Array(100)
                bad.fill(0xff)
                const ret = validatePrivateKey(id, bad, provider)
                expect(ret).toBe(false)
            })

            it('onesPrivateKey', () => {
                const onesKeyBytes = new Uint8Array(Nsk).fill(0xff)
                const ret = validatePrivateKey(id, onesKeyBytes, provider)
                expect(ret).toBe(false)
            })

            it('identityPublicKey', () => {
                const identityKeyBytes = gg.identity().serialize()
                const ret = validatePublicKey(id, identityKeyBytes, provider)
                expect(ret).toBe(false)
            })

            it('onesPublicKey', () => {
                const onesKeyBytes = new Uint8Array(Npk).fill(0xff)
                const ret = validatePublicKey(id, onesKeyBytes, provider)
                expect(ret).toBe(false)
            })

            it('generateKeyPair', async () => {
                for (let i = 0; i < 64; i++) {
                    const keys = await generateKeyPair(id, provider) // eslint-disable-line no-await-in-loop
                    const sk = validatePrivateKey(id, keys.privateKey, provider)
                    const pk = validatePublicKey(id, keys.publicKey, provider)
                    expect(sk).toBe(true)
                    expect(pk).toBe(true)
                }
            })

            it('deriveKeyPair', async () => {
                const info = new TextEncoder().encode('info used for derivation')
                for (let i = 0; i < 64; i++) {
                    const seed = crypto.getRandomValues(new Uint8Array(Nsk))
                    const keys = await deriveKeyPair(Oprf.Mode.OPRF, id, seed, info, provider) // eslint-disable-line no-await-in-loop
                    const sk = validatePrivateKey(id, keys.privateKey, provider)
                    const pk = validatePublicKey(id, keys.publicKey, provider)
                    expect(sk).toBe(true)
                    expect(pk).toBe(true)
                }
            })
        })
    })
})
