import { CryptoNoble } from '../../src/cryptoNoble.js'
// You may want to do this when 3rd party dependencies use voprf-ts
// import { Oprf as OprfCore } from '@cloudflare/voprf-ts'
// OprfCore.Crypto = CryptoNoble

import { webcrypto } from 'node:crypto'

import { Oprf, type OprfApi, type SuiteID } from '../../src/facade/index.js'

export async function facadeOprfExample(Oprf: OprfApi, suite: SuiteID = Oprf.Suite.P521_SHA512) {
    // Setup: Create client and server.
    const mode = Oprf.makeMode({
        mode: Oprf.Mode.OPRF,
        suite
    })
    const privateKey = await mode.keys.randomPrivate()

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
    // evaluation.proof <- does not have member

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

    // Step 4: redemption song!
    const verified = await server.verifyFinalize(inputBytes, output)

    console.log(`Example OPRF - SuiteID: ${mode.suite}`)
    console.log(`CryptoProvider: ${mode.crypto.id}`)
    console.log(`input  (${input.length} bytes): ${input}`)
    console.log(`output (${output.length} bytes): ${Buffer.from(output).toString('hex')}`)
    console.log(`verified: ${verified}\n`)
}

export async function facadePoprfExample(Oprf: OprfApi, suite: SuiteID = Oprf.Suite.P256_SHA256) {
    // Setup: Create client and server.
    const mode = Oprf.makeMode({
        mode: Oprf.Mode.POPRF,
        suite
    })
    const { privateKey, publicKey } = await mode.keys.generatePair()

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

    // Step 4: redemption song!
    const verified = await server.verifyFinalize(inputBytes, output, infoBytes)

    console.log(`Example POPRF - SuiteID: ${mode.suite}`)
    console.log(`CryptoProvider: ${mode.crypto.id}`)
    console.log(`input  (${input.length} bytes): ${input}`)
    console.log(`output (${output.length} bytes): ${Buffer.from(output).toString('hex')}`)
    console.log(`info   (${info.length} bytes): ${info}`)
    console.log(`verified: ${verified}\n`)
}

export async function facadeVoprfExample(Oprf: OprfApi, suite: SuiteID = Oprf.Suite.P384_SHA384) {
    // Setup: Create client and server.
    const mode = Oprf.makeMode({
        mode: Oprf.Mode.VOPRF,
        suite
    })
    const { privateKey, publicKey } = await mode.keys.generatePair()

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

    // Step 4: redemption song!
    const verified = await server.verifyFinalize(inputBytes, output)

    console.log(`Example VOPRF - SuiteID: ${mode.suite}`)
    console.log(`CryptoProvider: ${mode.crypto.id}`)
    console.log(`input  (${input.length} bytes): ${input}`)
    console.log(`output (${output.length} bytes): ${Buffer.from(output).toString('hex')}`)
    console.log(`verified: ${verified}\n`)
}

async function main() {
    try {
        if (typeof crypto === 'undefined') {
            Object.assign(global, { crypto: webcrypto })
        }
        await facadeOprfExample(Oprf)
        await facadeVoprfExample(Oprf)

        // This suite requires the noble crypto provider as sjcl doesn't support
        // ristretto.
        const OprfNoble = Oprf.withConfig({ crypto: CryptoNoble })
        await facadePoprfExample(OprfNoble, Oprf.Suite.RISTRETTO255_SHA512)
    } catch (_e: unknown) {
        const e = _e as Error
        console.log(`Error: ${e.message}`)
        console.log(`Stack: ${e.stack}`)
        process.exit(1)
    }
}

void main()
