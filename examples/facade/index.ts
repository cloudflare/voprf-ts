import { webcrypto } from 'node:crypto'

import type { OprfApi } from '../../src/facade/types.js'
import { Oprf } from '../../src/facade/impl.js'
import { CryptoNoble } from '../../src/cryptoNoble.js'
// noinspection ES6PreferShortImport
import { CryptoImpl } from '../../src/cryptoImpl.js'

export async function facadeOprfExample(Oprf: OprfApi) {
    // Setup: Create client and server.
    const mode = Oprf.makeMode({
        suite: Oprf.Suite.P521_SHA512,
        mode: Oprf.Mode.OPRF
    })
    const privateKey = await mode.randomPrivateKey()

    const server = mode.makeServer(privateKey)
    const client = mode.makeClient()

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
    console.log(`Example OPRF - SuiteID: ${mode.suiteID}`)
    console.log(`input  (${input.length} bytes): ${input}`)
    console.log(`output (${output.length} bytes): ${Buffer.from(output).toString('hex')}\n`)
}

export async function facadePoprfExample(Oprf: OprfApi) {
    // Setup: Create client and server.
    const mode = Oprf.makeMode({
        suite: Oprf.Suite.P256_SHA256,
        mode: Oprf.Mode.POPRF
    })
    const privateKey = await mode.randomPrivateKey()
    const publicKey = mode.generatePublicKey(privateKey)

    const server = mode.makeServer(privateKey)
    const client = mode.makeClient(publicKey)

    // Client                                       Server
    // ====================================================
    // Step 1: The client prepares arbitrary input that will be evaluated by the
    // server, the blinding method produces an evaluation request, and some
    // finalization data to be used later. Then, the client sends the evaluation
    // request to the server.

    const input = 'This is the client input'
    const info = 'Shared info between server and client'
    const inputBytes = new TextEncoder().encode(input)
    const infoBytes = new TextEncoder().encode(info)
    const [finData, evalReq] = await client.blind([inputBytes])

    // Step 2: Once the server received the evaluation request, it responds to
    // the client with an evaluation.
    const evaluation = await server.blindEvaluate(evalReq, infoBytes)

    // Step 3: Finally, the client can produce the output of the OPRF protocol
    // using the server's evaluation and the finalization data from the first
    // step. If the mode is verifiable, this step allows the client to check the
    // proof that the server used the expected private key for the evaluation.
    const [output] = await client.finalize(finData, evaluation, infoBytes)

    console.log(`Example POPRF - SuiteID: ${mode.suiteID}`)
    console.log(`input  (${input.length} bytes): ${input}`)
    console.log(`info  (${info.length} bytes): ${info}`)
    console.log(`output (${output.length} bytes): ${Buffer.from(output).toString('hex')}\n`)
}

export async function facadeVoprfExample(Oprf: OprfApi) {
    // Setup: Create client and server.
    const mode = Oprf.makeMode({
        suite: Oprf.Suite.P384_SHA384,
        mode: Oprf.Mode.VOPRF
    })
    const privateKey = await mode.randomPrivateKey()
    const publicKey = mode.generatePublicKey(privateKey)

    const server = mode.makeServer(privateKey)
    const client = mode.makeClient(publicKey)

    // Client                                       Server
    // ====================================================
    // Step 1: The client prepares arbitrary input that will be evaluated by the
    // server, the blinding method produces an evaluation request, and some
    // finalization data to be used later. Then, the client sends the evaluation
    // request to the server.

    const input = 'This is the client input'
    const inputBytes = new TextEncoder().encode(input)
    const [finData, evalReq] = await client.blind([inputBytes])

    // Step 2: Once the server received the evaluation request, it responds to
    // the client with an evaluation.
    const evaluation = await server.blindEvaluate(evalReq)

    // Step 3: Finally, the client can produce the output of the OPRF protocol
    // using the server's evaluation and the finalization data from the first
    // step. If the mode is verifiable, this step allows the client to check the
    // proof that the server used the expected private key for the evaluation.
    const [output] = await client.finalize(finData, evaluation)

    console.log(`Example VOPRF - SuiteID: ${mode.suiteID}`)
    console.log(`input  (${input.length} bytes): ${input}`)
    console.log(`output (${output.length} bytes): ${Buffer.from(output).toString('hex')}\n`)
}

async function main() {
    if (typeof crypto === 'undefined') {
        Object.assign(global, { crypto: webcrypto })
    }
    delete (CryptoImpl as { provider: unknown })['provider']


    await facadeOprfExample(Oprf)
    await facadeVoprfExample(Oprf)

    const OprfNoble = Oprf.withConfig({ crypto: CryptoNoble })
    delete (CryptoImpl as { provider: unknown })['provider']

    await facadePoprfExample(Oprf)
    await facadePoprfExample(OprfNoble)
}

main().catch(console.error)
