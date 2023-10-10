import type { CryptoProvider, HashID } from '../cryptoTypes.js'
import type { Elt, Group, Scalar } from '../groupTypes.js'
import type { MODE, SUITE } from './consts.js'

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

type ValueType<T> = T[keyof T]
export type ModeID = ValueType<typeof MODE>
export type SuiteID = ValueType<typeof SUITE>

export interface Parcelable<T> {
    isEqual(other: T): boolean

    serialize(): Uint8Array
}

export interface EvaluationRequest extends Parcelable<EvaluationRequest> {
    readonly blinded: Array<Elt>
}

export interface FinalizeData extends Parcelable<FinalizeData> {
    readonly inputs: Array<Uint8Array>
    readonly blinds: Array<Scalar>
    readonly evalReq: EvaluationRequest
}

export interface DLEQParams {
    // TODO: just use the GroupID ? and Group.fromID -> Group.get() with
    //  cached/getInstance semantics ?
    readonly gg: Group
    readonly dst: string
    readonly hashID: HashID
}

export interface DLEQProof extends Parcelable<DLEQProof> {
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

export interface KeyPair {
    privateKey: Uint8Array
    publicKey: Uint8Array
}

export interface KeySizes {
    privateKey: number
    publicKey: number
}

export interface KeyManager<M extends ModeID, S extends SuiteID> extends Modal<M, S> {
    getKeySizes(): KeySizes

    validatePrivateKey(privateKey: Uint8Array): boolean

    validatePublicKey(publicKey: Uint8Array): boolean

    randomPrivateKey(): Promise<Uint8Array>

    derivePrivateKey(seed: Uint8Array, info: Uint8Array): Promise<Uint8Array>

    generatePublicKey(privateKey: Uint8Array): Uint8Array

    generateKeyPair(): Promise<KeyPair>

    deriveKeyPair(seed: Uint8Array, info: Uint8Array): Promise<KeyPair>
}

export interface Mode<M extends ModeID, S extends SuiteID> extends KeyManager<M, S>, Modal<M, S> {
    makeServer(privateKey: Uint8Array): Server<M, S>

    makeClient: M extends MODEMAP['oprf']
        ? () => Client<M, S>
        : (publicKey: Uint8Array) => Client<M, S>
}

export interface OprfApi {
    Suite: typeof SUITE
    Mode: typeof MODE

    readonly crypto: CryptoProvider

    withConfiguration(config: { crypto: CryptoProvider }): OprfApi

    makeMode<M extends ModeID, S extends SuiteID>(params: { mode: M; suite: S }): Mode<M, S>
}
