// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    Blind,
    Blinded,
    Evaluation,
    EvaluationRequest,
    FinalizeData,
    ModeID,
    Oprf,
    SuiteID
} from './oprf.js'
import { Elt, Group, Scalar, SerializedElt } from './group.js'

class baseClient extends Oprf {
    constructor(mode: ModeID, suite: SuiteID) {
        super(mode, suite)
    }

    async randomBlinder(): Promise<{ scalar: Scalar; blind: Blind }> {
        const scalar = await this.gg.randomScalar()
        const blind = new Blind(this.gg.serializeScalar(scalar))
        return { scalar, blind }
    }

    async blind(input: Uint8Array): Promise<[FinalizeData, EvaluationRequest]> {
        const { scalar, blind } = await this.randomBlinder()
        const dst = this.getDST(Oprf.LABELS.HashToGroupDST)
        const P = await this.gg.hashToGroup(input, dst)
        if (this.gg.isIdentity(P)) {
            throw new Error('InvalidInputError')
        }
        const Q = Group.mul(scalar, P)
        const evalReq = new EvaluationRequest(new Blinded(this.gg.serialize(Q)))
        const finData = new FinalizeData(input, blind, evalReq)
        return [finData, evalReq]
    }

    doFinalize(
        finData: FinalizeData,
        evaluation: Evaluation,
        info = new Uint8Array(0)
    ): Promise<Uint8Array> {
        const blindScalar = this.gg.deserializeScalar(finData.blind)
        const blindScalarInv = this.gg.invScalar(blindScalar)
        const Z = this.gg.deserialize(evaluation.element)
        const N = Group.mul(blindScalarInv, Z)
        const unblinded = this.gg.serialize(N)
        return this.coreFinalize(finData.input, unblinded, info)
    }
}

export class OPRFClient extends baseClient {
    constructor(suite: SuiteID) {
        super(Oprf.Mode.OPRF, suite)
    }
    finalize(finData: FinalizeData, evaluation: Evaluation): Promise<Uint8Array> {
        return super.doFinalize(finData, evaluation)
    }
}

export class VOPRFClient extends baseClient {
    constructor(suite: SuiteID, private readonly pubKeyServer: Uint8Array) {
        super(Oprf.Mode.VOPRF, suite)
    }

    finalize(finData: FinalizeData, evaluation: Evaluation): Promise<Uint8Array> {
        if (!evaluation.proof) {
            throw new Error('no proof provided')
        }
        const pkS = this.gg.deserialize(new SerializedElt(this.pubKeyServer))
        const Q = this.gg.deserialize(finData.evalReq.blinded)
        const kQ = this.gg.deserialize(evaluation.element)
        if (!evaluation.proof.verify([this.gg.generator(), pkS], [Q, kQ])) {
            throw new Error('proof failed')
        }

        return super.doFinalize(finData, evaluation)
    }
}

export class POPRFClient extends baseClient {
    constructor(suite: SuiteID, private readonly pubKeyServer: Uint8Array) {
        super(Oprf.Mode.POPRF, suite)
    }

    private async pointFromInfo(info: Uint8Array): Promise<Elt> {
        const m = await this.scalarFromInfo(info)
        const T = this.gg.mulBase(m)
        const pkS = this.gg.deserialize(new SerializedElt(this.pubKeyServer))
        const tw = Group.add(T, pkS)
        if (tw.isIdentity) {
            throw new Error('invalid info')
        }
        return tw
    }

    async finalize(
        finData: FinalizeData,
        evaluation: Evaluation,
        info = new Uint8Array(0)
    ): Promise<Uint8Array> {
        if (!evaluation.proof) {
            throw new Error('no proof provided')
        }
        const tw = await this.pointFromInfo(info)
        const Q = this.gg.deserialize(evaluation.element)
        const kQ = this.gg.deserialize(finData.evalReq.blinded)
        if (!evaluation.proof.verify([this.gg.generator(), tw], [Q, kQ])) {
            throw new Error('proof failed')
        }
        return super.doFinalize(finData, evaluation, info)
    }
}
