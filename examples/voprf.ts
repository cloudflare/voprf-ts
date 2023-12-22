// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    Oprf,
    VOPRFClient,
    VOPRFServer,
    generatePublicKey,
    randomPrivateKey
} from '@cloudflare/voprf-ts'

// Example: VOPRF mode with the P384-SHA384 suite.
export async function voprfExample() {
    // Setup: Create client and server.
    const suite = Oprf.Suite.P384_SHA384
    const privateKey = await randomPrivateKey(suite)
    const publicKey = generatePublicKey(suite, privateKey)

    const server = new VOPRFServer(suite, privateKey)
    const client = new VOPRFClient(suite, publicKey)

    // Client                                       Server
    // ====================================================
    // Step 1: The client prepares arbitrary input that will be evaluated by the
    // server, the blinding method produces an evaluation request, and some
    // finalization data to be used later. Then, the client sends the evaluation
    // request to the server.
    //
    // Client
    // blind, blindedElement = Blind(input)
    const input = 'This is the client input'
    const inputBytes = new TextEncoder().encode(input)
    const [finData, evalReq] = await client.blind([inputBytes])
    //             evalReq
    //       ------------------>>
    //                                              Server
    // Step 2: Once the server received the evaluation request, it responds to
    // the client with an evaluation.
    //
    //          evaluation = BlindEvaluate(evalReq, info*)
    const evaluation = await server.blindEvaluate(evalReq)
    //            evaluation
    //       <<------------------
    //
    // Client
    // Step 3: Finally, the client can produce the output of the OPRF protocol
    // using the server's evaluation and the finalization data from the first
    // step. If the mode is verifiable, this step allows the client to check the
    // proof that the server used the expected private key for the evaluation.
    //
    // output = Finalize(finData, evaluation, info*)
    const [output] = await client.finalize(finData, evaluation)
    console.log(`Example VOPRF - SuiteID: ${Oprf.Suite.P384_SHA384}`)
    console.log(`input  (${input.length} bytes): ${input}`)
    console.log(`output (${output.length} bytes): ${Buffer.from(output).toString('hex')}\n`)
}
