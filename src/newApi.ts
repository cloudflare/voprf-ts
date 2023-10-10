export const MODE = {
    // Otherwise the type inference for Client<?> is Client<2>
    // can easily create some kind of utils to convert numbers to MODE
    // in any case, you need to when parsing tests
    // see: vector tests
    // const txtMode = Object.entries(Oprf.Mode)[mode as number][0]
    OPRF: 'oprf', // 0,
    VOPRF: 'voprf', // 1,
    POPRF: 'poprf' // 2
} as const

export const SUITE = {
    P256_SHA256: 'P256-SHA256',
    P384_SHA384: 'P384-SHA384',
    P521_SHA512: 'P521-SHA512',
    RISTRETTO255_SHA512: 'ristretto255-SHA512',
    DECAF448_SHAKE256: 'decaf448-SHAKE256'
} as const

type ValueType<T> = T[keyof T]

export type ModeID = ValueType<typeof MODE>
export type SuiteID = ValueType<typeof SUITE>

import type { CryptoProvider, HashID } from './cryptoTypes.js'
import type { Elt, Group, Scalar } from './groupTypes.js'

interface Parcelable<T> {
    isEqual(other: T): boolean

    serialize(): Uint8Array
}

interface KeyPair {
    privateKey: Uint8Array
    publicKey: Uint8Array
}

interface KeySizes {
    privateKey: number
    publicKey: number
}

interface KeyManager {
    getKeySizes(): KeySizes

    validatePrivateKey(privateKey: Uint8Array): boolean

    validatePublicKey(publicKey: Uint8Array): boolean

    randomPrivateKey(): Promise<Uint8Array>

    derivePrivateKey(seed: Uint8Array, info: Uint8Array): Promise<Uint8Array>

    generatePublicKey(privateKey: Uint8Array): Uint8Array

    generateKeyPair(): Promise<KeyPair>

    deriveKeyPair(seed: Uint8Array, info: Uint8Array): Promise<KeyPair>
}

interface DLEQParams {
    // TODO: just use the GroupID ?
    readonly gg: Group
    readonly dst: string
    readonly hashID: HashID
}

interface DLEQProof extends Parcelable<DLEQProof> {
    readonly params: Required<DLEQParams>
    readonly c: Scalar
    readonly s: Scalar

    verify(p0: [Elt, Elt], p1: [Elt, Elt]): Promise<boolean>

    verify_batch(p0: [Elt, Elt], p1s: Array<[Elt, Elt]>): Promise<boolean>
}

interface FinalizeData extends Parcelable<FinalizeData> {
    readonly inputs: Array<Uint8Array>
    readonly blinds: Array<Scalar>
    readonly evalReq: EvaluationRequest
}

interface EvaluationRequest extends Parcelable<EvaluationRequest> {
    readonly blinded: Array<Elt>
}

interface Evaluation extends Parcelable<Evaluation> {
    readonly mode: ModeID
    readonly evaluated: Array<Elt>
    readonly proof?: DLEQProof
}

interface Client<T extends ModeID> {
    blind(inputs: Uint8Array[]): Promise<[FinalizeData, EvaluationRequest]>

    finalize: T extends 'poprf'
        ? (
              finData: FinalizeData,
              evaluation: Evaluation,
              info?: Uint8Array
          ) => Promise<Array<Uint8Array>>
        : (finData: FinalizeData, evaluation: Evaluation) => Promise<Array<Uint8Array>>
}

interface Server<T extends ModeID> {
    blindEvaluate: T extends 'poprf'
        ? (req: EvaluationRequest, info?: Uint8Array) => Promise<Evaluation>
        : (req: EvaluationRequest) => Promise<Evaluation>

    evaluate: T extends 'poprf'
        ? (evaluate: Uint8Array, info?: Uint8Array) => Promise<boolean>
        : (evaluate: Uint8Array) => Promise<boolean>

    verifyFinalize: T extends 'poprf'
        ? (input: Uint8Array, output: Uint8Array, info?: Uint8Array) => Promise<boolean>
        : (input: Uint8Array, output: Uint8Array) => Promise<boolean>
}

interface Suite<T extends ModeID> extends KeyManager {
    modeID: T
    suiteID: SuiteID
    group: Group

    makeServer(privateKey: Uint8Array): Server<T>

    makeClient: T extends 'oprf' ? () => Client<T> : (publicKey: Uint8Array) => Client<T>
}

interface OprfApi {
    Suite: typeof SUITE
    Mode: typeof MODE

    readonly crypto: CryptoProvider

    withConfiguration(config: { crypto: CryptoProvider }): OprfApi

    makeSuite<T extends ModeID>(params: { mode: T; suite: SuiteID }): Suite<T>
}

export async function oprfExample(Oprf: OprfApi) {
    // Setup: Create client and server.
    const suite = Oprf.makeSuite({
        suite: Oprf.Suite.P521_SHA512,
        mode: Oprf.Mode.OPRF
    })
    const privateKey = await suite.randomPrivateKey()

    const server = suite.makeServer(privateKey)
    const client = suite.makeClient()

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
    console.log(`Example OPRF - SuiteID: ${Oprf.Suite.P521_SHA512}`)
    console.log(`input  (${input.length} bytes): ${input}`)
    console.log(`output (${output.length} bytes): ${Buffer.from(output).toString('hex')}\n`)
}

export async function poprfExample(Oprf: OprfApi) {
    // Setup: Create client and server.
    const suite = Oprf.makeSuite({
        suite: Oprf.Suite.P256_SHA256,
        mode: Oprf.Mode.POPRF
    })
    const privateKey = await suite.randomPrivateKey()
    const publicKey = suite.generatePublicKey(privateKey)

    const server = suite.makeServer(privateKey)
    const client = suite.makeClient(publicKey)

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

    console.log(`Example POPRF - SuiteID: ${Oprf.Suite.P256_SHA256}`)
    console.log(`input  (${input.length} bytes): ${input}`)
    console.log(`info  (${info.length} bytes): ${info}`)
    console.log(`output (${output.length} bytes): ${Buffer.from(output).toString('hex')}\n`)
}

export async function voprfExample(Oprf: OprfApi) {
    // Setup: Create client and server.
    const suite = Oprf.makeSuite({
        suite: Oprf.Suite.P384_SHA384,
        mode: Oprf.Mode.VOPRF
    })
    const privateKey = await suite.randomPrivateKey()
    const publicKey = suite.generatePublicKey(privateKey)

    const server = suite.makeServer(privateKey)
    const client = suite.makeClient(publicKey)

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

    console.log(`Example VOPRF - SuiteID: ${Oprf.Suite.P384_SHA384}`)
    console.log(`input  (${input.length} bytes): ${input}`)
    console.log(`output (${output.length} bytes): ${Buffer.from(output).toString('hex')}\n`)
}
