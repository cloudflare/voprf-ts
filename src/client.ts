// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { Elt, Scalar } from './groupTypes.js'
import type { Evaluation, SuiteID } from './oprf.js'
import { EvaluationRequest, FinalizeData, Oprf } from './oprf.js'

import { zip } from './util.js'
import type { CryptoProviderArg } from './cryptoImpl.js'
import { DLEQVerifier } from './dleq.js'

class baseClient extends Oprf {
    randomBlinder(): Promise<Scalar> {
        return this.group.randomScalar()
    }

    async blind(inputs: Uint8Array[]): Promise<[FinalizeData, EvaluationRequest]> {
        const eltList = []
        const blinds = []
        for (const input of inputs) {
            const scalar = await this.randomBlinder()
            const inputElement = await this.group.hashToGroup(
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
            const blindInv = finData.blinds[i | 0].inv()
            const N = evaluation.evaluated[i | 0].mul(blindInv)
            const unblinded = N.serialize()
            outputList.push(await this.coreFinalize(finData.inputs[i | 0], unblinded, info))
        }
        return outputList
    }
}

export class OPRFClient extends baseClient {
    constructor(suite: SuiteID, ...arg: CryptoProviderArg) {
        super(Oprf.Mode.OPRF, suite, ...arg)
    }

    finalize(finData: FinalizeData, evaluation: Evaluation): Promise<Array<Uint8Array>> {
        return super.doFinalize(finData, evaluation)
    }
}

export class VOPRFClient extends baseClient {
    constructor(
        suite: SuiteID,
        private readonly pubKeyServer: Uint8Array,
        ...arg: CryptoProviderArg
    ) {
        super(Oprf.Mode.VOPRF, suite, ...arg)
    }

    async finalize(finData: FinalizeData, evaluation: Evaluation): Promise<Array<Uint8Array>> {
        if (!evaluation.proof) {
            throw new Error('no proof provided')
        }
        const pkS = this.group.desElt(this.pubKeyServer)

        const n = finData.inputs.length
        if (evaluation.evaluated.length !== n) {
            throw new Error('mismatched lengths')
        }

        const verifier = new DLEQVerifier(this.getDLEQParams(), this.crypto)
        if (
            !(await verifier.verify_batch(
                [this.group.generator(), pkS],
                zip(finData.evalReq.blinded, evaluation.evaluated),
                evaluation.proof
            ))
        ) {
            throw new Error('proof failed')
        }

        return super.doFinalize(finData, evaluation)
    }
}

export class POPRFClient extends baseClient {
    constructor(
        suite: SuiteID,
        private readonly pubKeyServer: Uint8Array,
        ...arg: CryptoProviderArg
    ) {
        super(Oprf.Mode.POPRF, suite, ...arg)
    }

    private async pointFromInfo(info: Uint8Array): Promise<Elt> {
        const m = await this.scalarFromInfo(info)
        const T = this.group.mulGen(m)
        const pkS = this.group.desElt(this.pubKeyServer)
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

        const verifier = new DLEQVerifier(this.getDLEQParams(), this.crypto)
        if (
            !(await verifier.verify_batch(
                [this.group.generator(), tw],
                zip(evaluation.evaluated, finData.evalReq.blinded),
                evaluation.proof
            ))
        ) {
            throw new Error('proof failed')
        }
        return super.doFinalize(finData, evaluation, info)
    }
}
