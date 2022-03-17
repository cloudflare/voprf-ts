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
import { Group, Scalar } from './group.js'

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

    finalize(finData: FinalizeData, evaluation: Evaluation): Promise<Uint8Array> {
        const blindScalar = this.gg.deserializeScalar(finData.blind)
        const blindScalarInv = this.gg.invScalar(blindScalar)
        const Z = this.gg.deserialize(evaluation.element)
        const N = Group.mul(blindScalarInv, Z)
        const unblinded = this.gg.serialize(N)
        return this.coreFinalize(finData.input, unblinded)
    }
}

export class OPRFClient extends baseClient {
    constructor(suite: SuiteID) {
        super(Oprf.Mode.OPRF, suite)
    }
}
