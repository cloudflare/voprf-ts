// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { OPRFClient, OPRFServer, Oprf, randomPrivateKey } from '../src/index.js'

describe.each(Object.entries(Oprf.Suite))('oprf-workflow', (name, id) => {
    it(`${name}`, async () => {
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
        const [finData, evalReq] = await client.blind(input)
        // Client                     Server
        //             evalReq
        //       ------------------>>

        // Server
        const evaluation = await server.evaluate(evalReq)
        // Client                     Server
        //            evaluation
        //       <<------------------

        // Client
        const output = await client.finalize(finData, evaluation)
        expect(output).toHaveLength(Oprf.getOprfSize(id))

        const serverOutput = await server.fullEvaluate(input)
        expect(output).toStrictEqual(serverOutput)

        const success = await server.verifyFinalize(input, output)
        expect(success).toBe(true)
    })
})
