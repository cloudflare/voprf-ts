import type { CryptoProvider, HashID } from '../cryptoTypes.js'
import type { Elt, Group, Scalar } from '../groupTypes.js'

export const MODE = {
    // TODO: use string
    // Otherwise the type inference shown in IDES is for Client<?, ?> is Client<2, 'P256-SHA256'>
    // Could easily create some kind of utils to convert numbers to MODE
    // in any case, you already need to faff around
    // see: vector tests
    // const txtMode = Object.entries(Oprf.Mode)[mode as number][0]
    OPRF: 0, // 'oprf', // 0,
    VOPRF: 1, // 'voprf', // 1,
    POPRF: 2 // 'poprf' // 2
} as const

// TODO: this shouldn't be needed, but is while experimenting with string modes
// using number modes to retro type the old (implementing) client/servers to this
type MODEMAP = {
    oprf: 0
    voprf: 1
    poprf: 2
    [0]: 'oprf'
    [1]: 'voprf'
    [2]: 'poprf'
}

export const SUITE = {
    P256_SHA256: 'P256-SHA256',
    P384_SHA384: 'P384-SHA384',
    P521_SHA512: 'P521-SHA512',
    RISTRETTO255_SHA512: 'ristretto255-SHA512',
    DECAF448_SHAKE256: 'decaf448-SHAKE256'
} as const

type ValueType<T> = T[keyof T]
type ModeID = ValueType<typeof MODE>
type SuiteID = ValueType<typeof SUITE>

interface Parcelable<T> {
    isEqual(other: T): boolean

    serialize(): Uint8Array
}

interface EvaluationRequest extends Parcelable<EvaluationRequest> {
    readonly blinded: Array<Elt>
}

interface FinalizeData extends Parcelable<FinalizeData> {
    readonly inputs: Array<Uint8Array>
    readonly blinds: Array<Scalar>
    readonly evalReq: EvaluationRequest
}

interface DLEQParams {
    // TODO: just use the GroupID ? and Group.fromID -> Group.get() with
    //  cached/getInstance semantics ?
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

interface Evaluation extends Parcelable<Evaluation> {
    readonly mode: ModeID
    readonly evaluated: Array<Elt>
    readonly proof?: DLEQProof
}

export interface Modal<M extends ModeID, S extends SuiteID> {
    readonly modeID: M
    // This is just to check if this works
    readonly suiteID: S

    // TODO:
    readonly gg: Group
}

export interface Client<M extends ModeID = ModeID, S extends SuiteID = SuiteID>
    extends Modal<M, S> {
    blind(inputs: Uint8Array[]): Promise<[FinalizeData, EvaluationRequest]>

    finalize: M extends MODEMAP['poprf']
        ? (
              finData: FinalizeData,
              evaluation: Evaluation,
              info?: Uint8Array
          ) => Promise<Array<Uint8Array>>
        : (finData: FinalizeData, evaluation: Evaluation) => Promise<Array<Uint8Array>>
}

export interface Server<M extends ModeID = ModeID, S extends SuiteID = SuiteID>
    extends Modal<M, S> {
    blindEvaluate: M extends MODEMAP['poprf']
        ? (req: EvaluationRequest, info?: Uint8Array) => Promise<Evaluation>
        : (req: EvaluationRequest) => Promise<Evaluation>

    evaluate: M extends MODEMAP['poprf']
        ? (evaluate: Uint8Array, info?: Uint8Array) => Promise<Uint8Array>
        : (evaluate: Uint8Array) => Promise<Uint8Array>

    verifyFinalize: M extends MODEMAP['poprf']
        ? (input: Uint8Array, output: Uint8Array, info?: Uint8Array) => Promise<boolean>
        : (input: Uint8Array, output: Uint8Array) => Promise<boolean>

    constructDLEQParams(): DLEQParams
}

interface KeyPair {
    privateKey: Uint8Array
    publicKey: Uint8Array
}

interface KeySizes {
    privateKey: number
    publicKey: number
}

interface KeyManager<M extends ModeID, S extends SuiteID> extends Modal<M, S> {
    getKeySizes(): KeySizes

    validatePrivateKey(privateKey: Uint8Array): boolean

    validatePublicKey(publicKey: Uint8Array): boolean

    randomPrivateKey(): Promise<Uint8Array>

    derivePrivateKey(seed: Uint8Array, info: Uint8Array): Promise<Uint8Array>

    generatePublicKey(privateKey: Uint8Array): Uint8Array

    generateKeyPair(): Promise<KeyPair>

    deriveKeyPair(seed: Uint8Array, info: Uint8Array): Promise<KeyPair>
}

interface Mode<M extends ModeID, S extends SuiteID> extends KeyManager<M, S>, Modal<M, S> {
    makeServer(privateKey: Uint8Array): Server<M, S>

    makeClient: M extends MODEMAP['oprf']
        ? () => Client<M, S>
        : (publicKey: Uint8Array) => Client<M, S>
}

interface OprfApi {
    Suite: typeof SUITE
    Mode: typeof MODE

    readonly crypto: CryptoProvider

    withConfiguration(config: { crypto: CryptoProvider }): OprfApi

    makeMode<M extends ModeID, S extends SuiteID>(params: { mode: M; suite: S }): Mode<M, S>
}

export async function oprfExample(Oprf: OprfApi) {
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

export async function poprfExample(Oprf: OprfApi) {
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

export async function voprfExample(Oprf: OprfApi) {
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
