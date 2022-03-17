// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { Blinded, Evaluated, Evaluation, EvaluationRequest, ModeID, Oprf, SuiteID } from './oprf.js'
import { Group, SerializedScalar } from './group.js'

import { ctEqual } from './util.js'

class baseServer extends Oprf {
    private privateKey: Uint8Array

    public supportsWebCryptoOPRF = false

    constructor(mode: ModeID, suite: SuiteID, privateKey: Uint8Array) {
        super(mode, suite)
        this.privateKey = privateKey
    }

    evaluate(req: EvaluationRequest): Promise<Evaluation> {
        if (this.supportsWebCryptoOPRF) {
            return this.evaluateWebCrypto(req)
        }
        return Promise.resolve(this.evaluateSJCL(req))
    }

    private async evaluateWebCrypto(req: EvaluationRequest): Promise<Evaluation> {
        const key = await crypto.subtle.importKey(
            'raw',
            this.privateKey,
            {
                name: 'OPRF',
                namedCurve: this.gg.id
            },
            true,
            ['sign']
        )
        // webcrypto accepts only compressed points.
        let compressed = Uint8Array.from(req.blinded)
        if (req.blinded[0] === 0x04) {
            const P = this.gg.deserialize(req.blinded)
            compressed = Uint8Array.from(this.gg.serialize(P, true))
        }
        const evaluation = await crypto.subtle.sign('OPRF', key, compressed)
        return new Evaluation(new Evaluated(evaluation))
    }

    private evaluateSJCL(req: EvaluationRequest): Evaluation {
        const P = this.gg.deserialize(req.blinded)
        const serSk = new SerializedScalar(this.privateKey)
        const sk = this.gg.deserializeScalar(serSk)
        const Z = Group.mul(sk, P)
        return new Evaluation(new Evaluated(this.gg.serialize(Z)))
    }

    async fullEvaluate(input: Uint8Array): Promise<Uint8Array> {
        const dst = this.getDST(Oprf.LABELS.HashToGroupDST)
        const P = await this.gg.hashToGroup(input, dst)
        if (this.gg.isIdentity(P)) {
            throw new Error('InvalidInputError')
        }
        const issuedElement = new EvaluationRequest(new Blinded(this.gg.serialize(P)))
        const evaluation = await this.evaluate(issuedElement)
        return this.coreFinalize(input, evaluation.element)
    }

    async verifyFinalize(input: Uint8Array, output: Uint8Array): Promise<boolean> {
        return ctEqual(output, await this.fullEvaluate(input))
    }
}

export class OPRFServer extends baseServer {
    constructor(suite: SuiteID, privateKey: Uint8Array) {
        super(Oprf.Mode.OPRF, suite, privateKey)
    }
}
