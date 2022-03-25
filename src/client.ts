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
import { Elt, Scalar } from './group.js'

class baseClient extends Oprf {
    constructor(mode: ModeID, suite: SuiteID) {
        super(mode, suite)
    }

    async randomBlinder(): Promise<{ scalar: Scalar; blind: Blind }> {
        const scalar = await this.gg.randomScalar()
        const blind = new Blind(scalar.serialize())
        return { scalar, blind }
    }

    async blind(input: Uint8Array): Promise<[FinalizeData, EvaluationRequest]> {
        const { scalar, blind } = await this.randomBlinder()
        const P = await this.gg.hashToGroup(input, this.getDST(Oprf.LABELS.HashToGroupDST))
        if (P.isIdentity()) {
            throw new Error('InvalidInputError')
        }
        const Q = P.mul(scalar)
        const evalReq = new EvaluationRequest(new Blinded(Q.serialize()))
        const finData = new FinalizeData(input, blind, evalReq)
        return [finData, evalReq]
    }

    doFinalize(
        finData: FinalizeData,
        evaluation: Evaluation,
        info = new Uint8Array(0)
    ): Promise<Uint8Array> {
        const blindScalar = Scalar.deserialize(this.gg, finData.blind)
        const blindScalarInv = blindScalar.inv()
        const Z = Elt.deserialize(this.gg, evaluation.element)
        const N = Z.mul(blindScalarInv)
        const unblinded = N.serialize()
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
        const pkS = Elt.deserialize(this.gg, this.pubKeyServer)
        const Q = Elt.deserialize(this.gg, finData.evalReq.blinded)
        const kQ = Elt.deserialize(this.gg, evaluation.element)
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
        const T = this.gg.mulGen(m)
        const pkS = Elt.deserialize(this.gg, this.pubKeyServer)
        const tw = pkS.add(T)
        if (tw.isIdentity()) {
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
        const Q = Elt.deserialize(this.gg, evaluation.element)
        const kQ = Elt.deserialize(this.gg, finData.evalReq.blinded)
        if (!evaluation.proof.verify([this.gg.generator(), tw], [Q, kQ])) {
            throw new Error('proof failed')
        }
        return super.doFinalize(finData, evaluation, info)
    }
}
