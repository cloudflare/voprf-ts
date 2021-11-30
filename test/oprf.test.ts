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
            const te = new TextEncoder(),
                // /////////////////
                // Setup Server
                // /////////////////
                privateKey = await randomPrivateKey(id),
                server = new OPRFServer(id, privateKey),
                // /////////////////
                // Setup Client
                // /////////////////
                client = new OPRFClient(id),
                input = te.encode('This is the client input'),
                info = te.encode('This is the shared info'),
                // Client
                { blind, blindedElement } = await client.blind(input),
                // Client                     Server
                //          blindedElement
                //       ------------------>>

                // Server
                evaluatedElement = await server.evaluate(blindedElement, info),
                // Client                     Server
                //         evaluatedElement
                //       <<------------------

                // Client
                output = await client.finalize(input, info, blind, evaluatedElement),
                { outLenBytes } = hashParams(Oprf.params(id).hash)

            expect(output).toHaveLength(outLenBytes)

            const serverOutput = await server.fullEvaluate(input, info)
            expect(output).toStrictEqual(serverOutput)

            const success = await server.verifyFinalize(input, output, info)
            expect(success).toBe(true)
        })
    }
)
