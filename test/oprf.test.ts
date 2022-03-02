// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { OPRFClient, OPRFServer, Oprf, OprfID, randomPrivateKey } from '../src/index.js'

import { hashParams } from '../src/util.js'

describe.each([OprfID.OPRF_P256_SHA256, OprfID.OPRF_P384_SHA384, OprfID.OPRF_P521_SHA512])(
    'oprf-workflow',
    (id: OprfID) => {
        it(`${OprfID[id as number]}`, async () => {
            const te = new TextEncoder()
            // /////////////////
            // Setup Server
            // /////////////////
            const privateKey = await randomPrivateKey(id)
            const server = new OPRFServer(id, privateKey)
            // /////////////////
            // Setup Client
            // /////////////////
            const client = new OPRFClient(id)
            const input = te.encode('This is the client input')
            // Client
            const { blind, blindedElement } = await client.blind(input)
            // Client                     Server
            //          blindedElement
            //       ------------------>>

            // Server
            const evaluatedElement = await server.evaluate(blindedElement)
            // Client                     Server
            //         evaluatedElement
            //       <<------------------

            // Client
            const output = await client.finalize(input, blind, evaluatedElement)
            const { outLenBytes } = hashParams(Oprf.params(id).hash)

            expect(output).toHaveLength(outLenBytes)

            const serverOutput = await server.fullEvaluate(input)
            expect(output).toStrictEqual(serverOutput)

            const success = await server.verifyFinalize(input, output)
            expect(success).toBe(true)
        })
    }
)
