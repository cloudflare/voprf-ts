// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { DLEQParams, DLEQProver } from './dleq.js'
import { Elt, Scalar } from './group.js'
import { Evaluation, EvaluationRequest, ModeID, Oprf, SuiteID } from './oprf.js'
import { ctEqual, zip } from './util.js'

class baseServer extends Oprf {
    protected privateKey: Uint8Array

    public supportsWebCryptoOPRF = false

    constructor(mode: ModeID, suite: SuiteID, privateKey: Uint8Array) {
        super(mode, suite)
        this.privateKey = privateKey
    }

    protected doEvaluation(blinded: Elt, key: Uint8Array): Promise<Elt> {
        return this.supportsWebCryptoOPRF
            ? this.evaluateWebCrypto(blinded, key)
            : Promise.resolve(this.evaluateSJCL(blinded, key))
    }

    private async evaluateWebCrypto(blinded: Elt, key: Uint8Array): Promise<Elt> {
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
        const compressed = blinded.serialize(true)
        const evalBytes = new Uint8Array(await crypto.subtle.sign('OPRF', crKey, compressed))
        return Elt.deserialize(this.gg, evalBytes)
    }

    private evaluateSJCL(blinded: Elt, key: Uint8Array): Elt {
        return blinded.mul(Scalar.deserialize(this.gg, key))
    }

    protected async secretFromInfo(info: Uint8Array): Promise<[Scalar, Scalar]> {
        const m = await this.scalarFromInfo(info)
        const skS = Scalar.deserialize(this.gg, this.privateKey)
        const t = m.add(skS)
        if (t.isZero()) {
            throw new Error('inverse of zero')
        }
        const tInv = t.inv()
        return [t, tInv]
    }

    protected async doFullEvaluate(
        input: Uint8Array,
        info = new Uint8Array(0)
    ): Promise<Uint8Array> {
        let secret = this.privateKey
        if (this.mode === Oprf.Mode.POPRF) {
            const [, evalSecret] = await this.secretFromInfo(info)
            secret = evalSecret.serialize()
        }

        const P = await this.gg.hashToGroup(input, this.getDST(Oprf.LABELS.HashToGroupDST))
        if (P.isIdentity()) {
            throw new Error('InvalidInputError')
        }
        const evaluated = await this.doEvaluation(P, secret)
        return this.coreFinalize(input, evaluated.serialize(true), info)
    }

    constructDLEQParams(): DLEQParams {
        return { gg: this.gg, hash: this.hash, dst: '' }
    }
}

export class OPRFServer extends baseServer {
    constructor(suite: SuiteID, privateKey: Uint8Array) {
        super(Oprf.Mode.OPRF, suite, privateKey)
    }

    async evaluate(req: EvaluationRequest): Promise<Evaluation> {
        return new Evaluation(
            this.mode,
            await Promise.all(req.blinded.map((b) => this.doEvaluation(b, this.privateKey)))
        )
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
        const evalList = await Promise.all(
            req.blinded.map((b) => this.doEvaluation(b, this.privateKey))
        )
        const prover = new DLEQProver(this.constructDLEQParams())
        const skS = Scalar.deserialize(this.gg, this.privateKey)
        const pkS = this.gg.mulGen(skS)
        const proof = await prover.prove_batch(
            skS,
            [this.gg.generator(), pkS],
            zip(req.blinded, evalList)
        )
        return new Evaluation(this.mode, evalList, proof)
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
        const secret = evalSecret.serialize()
        const evalList = await Promise.all(req.blinded.map((b) => this.doEvaluation(b, secret)))
        const prover = new DLEQProver(this.constructDLEQParams())
        const kG = this.gg.mulGen(keyProof)
        const proof = await prover.prove_batch(
            keyProof,
            [this.gg.generator(), kG],
            zip(evalList, req.blinded)
        )
        return new Evaluation(this.mode, evalList, proof)
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
