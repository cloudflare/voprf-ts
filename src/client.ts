// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { Elt, Scalar } from './group.js'
import { Evaluation, EvaluationRequest, FinalizeData, ModeID, Oprf, SuiteID } from './oprf.js'

import { zip } from './util.js'

class baseClient extends Oprf {
    constructor(mode: ModeID, suite: SuiteID) {
        super(mode, suite)
    }

    randomBlinder(): Promise<Scalar> {
        return this.gg.randomScalar()
    }

    async blind(inputs: Uint8Array[]): Promise<[FinalizeData, EvaluationRequest]> {
        const eltList = []
        const blinds = []
        for (const input of inputs) {
            const scalar = await this.randomBlinder()
            const inputElement = await this.gg.hashToGroup(
                input,
                this.getDST(Oprf.LABELS.HashToGroupDST)
            )
            if (inputElement.isIdentity()) {
                throw new Error('InvalidInputError')
            }
            eltList.push(inputElement.mul(scalar))
            blinds.push(scalar)
        }
        const evalReq = new EvaluationRequest(eltList)
        const finData = new FinalizeData(inputs, blinds, evalReq)
        return [finData, evalReq]
    }

    async doFinalize(
        finData: FinalizeData,
        evaluation: Evaluation,
        info = new Uint8Array(0)
    ): Promise<Uint8Array[]> {
        const n = finData.inputs.length
        if (finData.blinds.length !== n || evaluation.evaluated.length !== n) {
            throw new Error('mismatched lengths')
        }

        const outputList = []
        for (let i = 0; i < n; i++) {
            const blindInv = finData.blinds[i as number].inv()
            const N = evaluation.evaluated[i as number].mul(blindInv)
            const unblinded = N.serialize()
            outputList.push(await this.coreFinalize(finData.inputs[i as number], unblinded, info))
        }
        return outputList
    }
}

export class OPRFClient extends baseClient {
    constructor(suite: SuiteID) {
        super(Oprf.Mode.OPRF, suite)
    }
    finalize(finData: FinalizeData, evaluation: Evaluation): Promise<Array<Uint8Array>> {
        return super.doFinalize(finData, evaluation)
    }
}

export class VOPRFClient extends baseClient {
    constructor(suite: SuiteID, private readonly pubKeyServer: Uint8Array) {
        super(Oprf.Mode.VOPRF, suite)
    }

    finalize(finData: FinalizeData, evaluation: Evaluation): Promise<Array<Uint8Array>> {
        if (!evaluation.proof) {
            throw new Error('no proof provided')
        }
        const pkS = Elt.deserialize(this.gg, this.pubKeyServer)

        const n = finData.inputs.length
        if (evaluation.evaluated.length !== n) {
            throw new Error('mismatched lengths')
        }

        if (
            !evaluation.proof.verify_batch(
                [this.gg.generator(), pkS],
                zip(finData.evalReq.blinded, evaluation.evaluated)
            )
        ) {
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
    ): Promise<Array<Uint8Array>> {
        if (!evaluation.proof) {
            throw new Error('no proof provided')
        }
        const tw = await this.pointFromInfo(info)
        const n = finData.inputs.length
        if (evaluation.evaluated.length !== n) {
            throw new Error('mismatched lengths')
        }

        if (
            !evaluation.proof.verify_batch(
                [this.gg.generator(), tw],
                zip(evaluation.evaluated, finData.evalReq.blinded)
            )
        ) {
            throw new Error('proof failed')
        }
        return super.doFinalize(finData, evaluation, info)
    }
}
