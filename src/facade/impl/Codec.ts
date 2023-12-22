import type {
    BaseEvaluation as FacadeEvaluationBase,
    VerifiableEvaluation as FacadeVerifiableEvaluation,
    Serialized,
    EvaluationRequest as FacadeEvaluationRequest,
    HasSerialize
} from '../types.js'
import type { Group, Elt, Scalar } from '../../groupTypes.js'
import type { CryptoProvider } from '../../cryptoTypes.js'
import { DLEQProof } from '../../dleq.js'
import { Evaluation, EvaluationRequest } from '../../oprf.js'

export type FacadeEvaluation = FacadeEvaluationBase & Partial<FacadeVerifiableEvaluation>

export class Codec {
    constructor(
        private group: Group,
        private crypto: CryptoProvider
    ) {}

    decodeElts(evaluated: Array<Serialized<Elt>>): Elt[] {
        return evaluated.map(this.group.desElt.bind(this.group))
    }

    decodeScalars(evaluated: Array<Serialized<Scalar>>): Scalar[] {
        return evaluated.map(this.group.desScalar.bind(this.group))
    }

    encodeArray(array: HasSerialize<Uint8Array>[]): Uint8Array[] {
        return array.map((e) => e.serialize())
    }

    decodeProof(proof: Uint8Array) {
        return DLEQProof.deserialize(this.group.id, proof, this.crypto)
    }

    encodeEvaluation(lib: Evaluation): FacadeEvaluation {
        return {
            proof: lib.proof ? lib.proof.serialize() : undefined,
            mode: lib.mode,
            evaluated: this.encodeArray(lib.evaluated)
        }
    }

    encodeEvaluationRequest(evalRequest: EvaluationRequest): FacadeEvaluationRequest {
        return {
            blinded: this.encodeArray(evalRequest.blinded)
        }
    }

    decodeEvaluation(fac: FacadeEvaluation): Evaluation {
        return new Evaluation(
            fac.mode,
            this.decodeElts(fac.evaluated),
            fac.proof ? this.decodeProof(fac.proof) : undefined
        )
    }

    decodeEvaluationRequest(fac: FacadeEvaluationRequest) {
        return new EvaluationRequest(this.decodeElts(fac.blinded))
    }
}
