// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { Elt, Group, OPRFClient, OPRFServer, Oprf, Scalar, randomPrivateKey } from '../src/index.js'

import { jest } from '@jest/globals'

const { sign, importKey } = crypto.subtle

interface CryptoKeyWithBuffer extends CryptoKey {
    keyData: ArrayBuffer
}

function mockImportKey(...x: Parameters<typeof importKey>): ReturnType<typeof importKey> {
    const [format, keyData, algorithm, extractable] = x
    if (format === 'raw' && (algorithm as EcKeyImportParams).name === 'OPRF') {
        return Promise.resolve({
            type: 'public',
            algorithm: {
                name: (algorithm as EcKeyImportParams).namedCurve
            },
            usages: ['sign'],
            extractable,
            keyData
        } as CryptoKeyWithBuffer)
    }
    throw new Error('bad algorithm')
}

function mockSign(...x: Parameters<typeof sign>): ReturnType<typeof sign> {
    const [algorithm, key, data] = x
    if (algorithm === 'OPRF') {
        const g = new Group(Group.getID((key.algorithm as EcdsaParams).name))
        const P = Elt.deserialize(g, new Uint8Array(data as ArrayBuffer))
        const serSk = new Uint8Array((key as CryptoKeyWithBuffer).keyData)
        const sk = Scalar.deserialize(g, serSk)
        const Z = P.mul(sk)
        const serZ = Z.serialize()
        return Promise.resolve(serZ.buffer as ArrayBuffer)
    }
    throw new Error('bad algorithm')
}

describe.each(Object.entries(Oprf.Suite))('supportsWebCrypto', (name, id) => {
    beforeAll(() => {
        jest.spyOn(crypto.subtle, 'importKey').mockImplementation(mockImportKey)
        jest.spyOn(crypto.subtle, 'sign').mockImplementation(mockSign)
    })

    it(`${name}`, async () => {
        const te = new TextEncoder()
        const privateKey = await randomPrivateKey(id)
        const server = new OPRFServer(id, privateKey)
        const client = new OPRFClient(id)
        const input = te.encode('This is the client input')
        const [, reqEval] = await client.blind([input])

        server.supportsWebCryptoOPRF = false
        const ev0 = await server.evaluate(reqEval)

        server.supportsWebCryptoOPRF = true
        const ev1 = await server.evaluate(reqEval)

        expect(ev0).toEqual(ev1)
    })
})
