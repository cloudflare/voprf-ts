// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { Blinded, Evaluation, Oprf, OprfID } from './oprf.js'
import { Group, SerializedScalar } from './group.js'

import { ctEqual } from './util.js'

export class OPRFServer extends Oprf {
    private privateKey: Uint8Array

    public supportsWebCryptoOPRF = false

    constructor(id: OprfID, privateKey: Uint8Array) {
        super(id)
        this.privateKey = privateKey
    }

    evaluate(blindedElement: Blinded): Promise<Evaluation> {
        if (this.supportsWebCryptoOPRF) {
            return this.evaluateWebCrypto(blindedElement)
        }
        return Promise.resolve(this.evaluateSJCL(blindedElement))
    }

    private async evaluateWebCrypto(blindedElement: Blinded): Promise<Evaluation> {
        const key = await crypto.subtle.importKey(
            'raw',
            this.privateKey,
            {
                name: 'OPRF',
                namedCurve: this.params.gg.id
            },
            true,
            ['sign']
        )
        // webcrypto accepts only compressed points.
        let compressed = Uint8Array.from(blindedElement)
        if (blindedElement[0] === 0x04) {
            const P = this.params.gg.deserialize(blindedElement)
            compressed = Uint8Array.from(this.params.gg.serialize(P, true))
        }
        const evaluation = await crypto.subtle.sign('OPRF', key, compressed)
        return new Evaluation(evaluation)
    }

    private evaluateSJCL(blindedElement: Blinded): Evaluation {
        const P = this.params.gg.deserialize(blindedElement),
            serSk = new SerializedScalar(this.privateKey),
            sk = this.params.gg.deserializeScalar(serSk),
            Z = Group.mul(sk, P)
        return new Evaluation(this.params.gg.serialize(Z))
    }

    async fullEvaluate(input: Uint8Array): Promise<Uint8Array> {
        const dst = Oprf.getHashToGroupDST(this.params.id),
            T = await this.params.gg.hashToGroup(input, dst),
            issuedElement = new Blinded(this.params.gg.serialize(T)),
            evaluation = await this.evaluate(issuedElement),
            digest = await this.coreFinalize(input, evaluation)
        return digest
    }

    async verifyFinalize(input: Uint8Array, output: Uint8Array): Promise<boolean> {
        const digest = await this.fullEvaluate(input)
        return ctEqual(output, digest)
    }
}
