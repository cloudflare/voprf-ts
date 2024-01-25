import type { CryptoProvider, HashID } from '../cryptoTypes.js'
import type { Elt, Group, Scalar, GroupID } from '../groupTypes.js'
import type { MODE, SUITE } from '../consts.js'

export type SuiteID = (typeof SUITE)[keyof typeof SUITE]
export type ModeOprf = typeof MODE.OPRF
export type ModePoprf = typeof MODE.POPRF
export type ModeVoprf = typeof MODE.VOPRF
export type ModeID = ModeOprf | ModeVoprf | ModePoprf

export type HasSerialize<T> = { serialize(): T }
export type Serialized<T extends HasSerialize<unknown>> =
    T extends HasSerialize<infer R> ? R : never

export interface Modal<M extends ModeID> {
    readonly mode: M
    readonly suite: SuiteID
}

export interface UsesCrypto {
    readonly crypto: CryptoProvider
    readonly group: Group
}

export type DLEQProof = { c: Scalar; s: Scalar; serialize(): Uint8Array }
// OPRF protocol only specifies encodings for these elements
export type OPRFElement = Elt | Scalar | DLEQProof

// So we only encode elements/bytes, and leave packet encoding to application layer
export interface EvaluationRequest {
    readonly blinded: Array<Serialized<Elt>>
}

export interface BaseEvaluation {
    readonly mode: ModeID
    readonly evaluated: Array<Serialized<Elt>>
}

export interface VerifiableEvaluation extends BaseEvaluation {
    readonly proof: Serialized<DLEQProof>
}

export interface FinalizeData {
    readonly inputs: Array<Uint8Array>
    readonly blinds: Array<Scalar>
    readonly evalReq: {
        readonly blinded: Array<Elt> // Keep wet elements
    }
}

export interface KeyPair {
    readonly privateKey: Uint8Array
    readonly publicKey: Uint8Array
}

export interface KeySizes {
    readonly privateKey: number
    readonly publicKey: number
}

export interface KeyManager extends Modal<ModeID>, UsesCrypto {
    sizes(): KeySizes

    validatePrivate(privateKey: Uint8Array): boolean

    validatePublic(publicKey: Uint8Array): boolean

    randomPrivate(): Promise<Uint8Array>

    derivePrivate(seed: Uint8Array, info: Uint8Array): Promise<Uint8Array>

    generatePublic(privateKey: Uint8Array): Uint8Array

    generatePair(): Promise<KeyPair>

    derivePair(seed: Uint8Array, info: Uint8Array): Promise<KeyPair>
}

// Using the tuple labels `info?:` gives us a nice IDE experience
type Info<M> = M extends ModePoprf ? [info?: Uint8Array] : []
type Evaluation<M extends ModeID> = M extends ModeOprf ? BaseEvaluation : VerifiableEvaluation
type PublicKey<M extends ModeID = ModeID> = M extends ModeOprf ? [] : [publicKey: Uint8Array]

export interface OprfBase<M extends ModeID> extends Modal<M>, UsesCrypto {}

export interface Client<M extends ModeID = ModeID> extends OprfBase<M> {
    spyHandle: {
        blinds: {
            randomBlinder(): Promise<Scalar>
        }
    }

    blind(inputs: Uint8Array[]): Promise<[FinalizeData, EvaluationRequest]>

    finalize(
        finData: FinalizeData,
        evaluation: Omit<Evaluation<M>, 'mode'>,
        ...info: Info<M>
    ): Promise<Array<Uint8Array>>
}

export interface Server<M extends ModeID = ModeID> extends OprfBase<M> {
    spyHandle: {
        dleqProver: {
            randomScalar(): Promise<Scalar>
        }
    }

    blindEvaluate(req: EvaluationRequest, ...info: Info<M>): Promise<Evaluation<M>>

    verifyFinalize(input: Uint8Array, output: Uint8Array, ...info: Info<M>): Promise<boolean>
}

export interface ModeParams<M extends ModeID = ModeID> extends Modal<M> {
    group: GroupID
    hash: HashID
    sizes: {
        elt: number
        scalar: number
        proof: number
        output: number
    }
}

export interface Mode<M extends ModeID = ModeID> extends Modal<M>, UsesCrypto {
    params: ModeParams<M>

    readonly keys: KeyManager

    makeServer(privateKey: Uint8Array): Server<M>

    makeClient(...publicKey: PublicKey<M>): Client<M>
}

export interface MakeModeParams<M extends ModeID> extends Modal<M> {}

export interface OprfApi {
    readonly Suite: typeof SUITE
    readonly Mode: typeof MODE

    readonly crypto: CryptoProvider

    withConfig(config: { crypto: CryptoProvider }): OprfApi

    makeMode<M extends ModeID>(params: MakeModeParams<M>): Mode<M>
}
