// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    Blinded,
    Group,
    OPRFClient,
    OPRFServer,
    Oprf,
    OprfID,
    SerializedElt,
    SerializedScalar,
    randomPrivateKey
} from '../src/index.js'

import { jest } from '@jest/globals'

const { sign, importKey } = crypto.subtle

function mockImportKey(...x: Parameters<typeof importKey>): ReturnType<typeof importKey> {
    const [format, keyData, algorithm, extractable] = x
    if (format === 'raw' && (algorithm as EcKeyImportParams).name === 'OPRF') {
        return Promise.resolve({
            type: 'public',
            algorithm: { name: (algorithm as EcKeyImportParams).namedCurve },
            usages: ['sign'],
            extractable,
            keyData
        })
    }
    throw new Error('bad algorithm')
}

function mockSign(...x: Parameters<typeof sign>): ReturnType<typeof sign> {
    const [algorithm, key, data] = x
    if (algorithm === 'OPRF') {
        const g = new Group(Group.getID((key.algorithm as EcdsaParams).name))
        const P = g.deserialize(new SerializedElt(data as Uint8Array))
        const serSk = new SerializedScalar((key as any).keyData)
        const sk = g.deserializeScalar(serSk)
        const Z = Group.mul(sk, P)
        const serZ = g.serialize(Z)
        return Promise.resolve(serZ.buffer as ArrayBuffer)
    }
    throw new Error('bad algorithm')
}

describe.each([OprfID.OPRF_P256_SHA256, OprfID.OPRF_P384_SHA384, OprfID.OPRF_P521_SHA512])(
    'supportsWebCrypto',
    (id: OprfID) => {
        beforeAll(() => {
            jest.spyOn(crypto.subtle, 'importKey').mockImplementation(mockImportKey)
            jest.spyOn(crypto.subtle, 'sign').mockImplementation(mockSign)
        })

        it(`${OprfID[id as number]}`, async () => {
            const te = new TextEncoder()
            const privateKey = await randomPrivateKey(id)
            const server = new OPRFServer(id, privateKey)
            const client = new OPRFClient(id)
            const input = te.encode('This is the client input')
            const req = await client.blind(input)
            const { gg } = Oprf.params(id)
            const bt = gg.deserialize(req.blindedElement)

            for (const compressed of [true, false]) {
                server.supportsWebCryptoOPRF = false
                let blinded = new Blinded(gg.serialize(bt, compressed))
                const ev0 = await server.evaluate(blinded) // eslint-disable-line no-await-in-loop

                server.supportsWebCryptoOPRF = true
                blinded = new Blinded(gg.serialize(bt, compressed))
                const ev1 = await server.evaluate(blinded) // eslint-disable-line no-await-in-loop

                expect(ev0).toEqual(ev1)
            }
        })
    }
)
