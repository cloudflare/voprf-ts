// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { Blinded, Evaluated, Evaluation, EvaluationRequest, ModeID, Oprf, SuiteID } from './oprf.js'
import { Group, Scalar, SerializedScalar } from './group.js'

import { DLEQProver } from './dleq.js'
import { ctEqual } from './util.js'

class baseServer extends Oprf {
    protected privateKey: Uint8Array

    public supportsWebCryptoOPRF = false

    constructor(mode: ModeID, suite: SuiteID, privateKey: Uint8Array) {
        super(mode, suite)
        this.privateKey = privateKey
    }

    protected doEvaluation(bl: Blinded, key: Uint8Array): Promise<Evaluated> {
        if (this.supportsWebCryptoOPRF) {
            return this.evaluateWebCrypto(bl, key)
        }
        return Promise.resolve(this.evaluateSJCL(bl, key))
    }

    private async evaluateWebCrypto(bl: Blinded, key: Uint8Array): Promise<Evaluated> {
        const crKey = await crypto.subtle.importKey(
            'raw',
            key,
            {
                name: 'OPRF',
                namedCurve: this.gg.id
            },
            true,
            ['sign']
        )
        // webcrypto accepts only compressed points.
        let compressed = Uint8Array.from(bl)
        if (bl[0] === 0x04) {
            const P = this.gg.deserialize(bl)
            compressed = Uint8Array.from(this.gg.serialize(P, true))
        }
        return new Evaluated(await crypto.subtle.sign('OPRF', crKey, compressed))
    }

    private evaluateSJCL(bl: Blinded, key: Uint8Array): Evaluated {
        const P = this.gg.deserialize(bl)
        const sk = this.gg.deserializeScalar(new SerializedScalar(key))
        const Z = Group.mul(sk, P)
        return new Evaluated(this.gg.serialize(Z))
    }

    protected async secretFromInfo(info: Uint8Array): Promise<[Scalar, Scalar]> {
        const m = await this.scalarFromInfo(info)
        const skS = this.gg.deserializeScalar(new SerializedScalar(this.privateKey))
        const t = this.gg.addScalar(m, skS)
        if (this.gg.isScalarZero(t)) {
            throw new Error('inverse of zero')
        }
        const tInv = this.gg.invScalar(t)
        return [t, tInv]
    }

    protected async doFullEvaluate(
        input: Uint8Array,
        info = new Uint8Array(0)
    ): Promise<Uint8Array> {
        let secret = this.privateKey
        if (this.mode === Oprf.Mode.POPRF) {
            const [, evalSecret] = await this.secretFromInfo(info)
            secret = this.gg.serializeScalar(evalSecret)
        }

        const P = await this.gg.hashToGroup(input, this.getDST(Oprf.LABELS.HashToGroupDST))
        if (this.gg.isIdentity(P)) {
            throw new Error('InvalidInputError')
        }
        const blinded = new Blinded(this.gg.serialize(P))
        const evaluated = await this.doEvaluation(blinded, secret)
        return this.coreFinalize(input, evaluated, info)
    }
}

export class OPRFServer extends baseServer {
    constructor(suite: SuiteID, privateKey: Uint8Array) {
        super(Oprf.Mode.OPRF, suite, privateKey)
    }

    async evaluate(req: EvaluationRequest): Promise<Evaluation> {
        return new Evaluation(await this.doEvaluation(req.blinded, this.privateKey))
    }
    async fullEvaluate(input: Uint8Array): Promise<Uint8Array> {
        return this.doFullEvaluate(input)
    }
    async verifyFinalize(input: Uint8Array, output: Uint8Array): Promise<boolean> {
        return ctEqual(output, await this.doFullEvaluate(input))
    }
}

export class VOPRFServer extends baseServer {
    constructor(suite: SuiteID, privateKey: Uint8Array) {
        super(Oprf.Mode.VOPRF, suite, privateKey)
    }
    async evaluate(req: EvaluationRequest): Promise<Evaluation> {
        const e = await this.doEvaluation(req.blinded, this.privateKey)
        const prover = new DLEQProver({ gg: this.gg, hash: this.hash, dst: '' })
        const skS = this.gg.deserializeScalar(new SerializedScalar(this.privateKey))
        const pkS = this.gg.mulBase(skS)
        const Q = this.gg.deserialize(req.blinded)
        const kQ = this.gg.deserialize(e)
        const proof = await prover.prove(skS, [this.gg.generator(), pkS], [Q, kQ])
        return new Evaluation(e, proof)
    }
    async fullEvaluate(input: Uint8Array): Promise<Uint8Array> {
        return this.doFullEvaluate(input)
    }
    async verifyFinalize(input: Uint8Array, output: Uint8Array): Promise<boolean> {
        return ctEqual(output, await this.doFullEvaluate(input))
    }
}

export class POPRFServer extends baseServer {
    constructor(suite: SuiteID, privateKey: Uint8Array) {
        super(Oprf.Mode.POPRF, suite, privateKey)
    }
    async evaluate(req: EvaluationRequest, info = new Uint8Array(0)): Promise<Evaluation> {
        const [keyProof, evalSecret] = await this.secretFromInfo(info)
        const secret = this.gg.serializeScalar(evalSecret)
        const e = await this.doEvaluation(req.blinded, secret)
        const prover = new DLEQProver({ gg: this.gg, hash: this.hash, dst: '' })
        const kG = this.gg.mulBase(keyProof)
        const Q = this.gg.deserialize(e)
        const kQ = this.gg.deserialize(req.blinded)
        const proof = await prover.prove(keyProof, [this.gg.generator(), kG], [Q, kQ])
        return new Evaluation(e, proof)
    }
    async fullEvaluate(input: Uint8Array, info = new Uint8Array(0)): Promise<Uint8Array> {
        return this.doFullEvaluate(input, info)
    }
    async verifyFinalize(
        input: Uint8Array,
        output: Uint8Array,
        info = new Uint8Array(0)
    ): Promise<boolean> {
        return ctEqual(output, await this.doFullEvaluate(input, info))
    }
}
