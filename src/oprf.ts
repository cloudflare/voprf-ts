// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { Group, GroupID, SerializedElt, SerializedScalar } from './group.js'
import { joinAll, to16bits } from './util.js'

export class Blind extends SerializedScalar {
    readonly _BlindBrand = ''
}
export class Blinded extends SerializedElt {
    readonly _BlindedBrand = ''
}

export class Evaluation extends SerializedElt {
    readonly _EvaluationBrand = ''
}

export enum OprfID { // eslint-disable-line no-shadow
    OPRF_P256_SHA256 = 3,
    OPRF_P384_SHA384 = 4,
    OPRF_P521_SHA512 = 5
}

export interface OprfParams {
    readonly id: OprfID
    readonly gg: Group
    readonly hash: string
    readonly blindedSize: number
    readonly evaluationSize: number
    readonly blindSize: number
}

export abstract class Oprf {
    static readonly mode = 0

    static readonly version = 'VOPRF09-'

    readonly params: OprfParams

    constructor(id: OprfID) {
        this.params = Oprf.params(id)
    }

    static validateID(id: OprfID): boolean {
        switch (id) {
            case OprfID.OPRF_P256_SHA256:
            case OprfID.OPRF_P384_SHA384:
            case OprfID.OPRF_P521_SHA512:
                return true
            default:
                throw new Error(`not supported ID: ${id}`)
        }
    }

    static params(id: OprfID): OprfParams {
        Oprf.validateID(id)
        let gid = GroupID.P256,
            hash = 'SHA-256'
        switch (id) {
            case OprfID.OPRF_P256_SHA256:
                break
            case OprfID.OPRF_P384_SHA384:
                gid = GroupID.P384
                hash = 'SHA-384'
                break
            case OprfID.OPRF_P521_SHA512:
                gid = GroupID.P521
                hash = 'SHA-512'
                break
            default:
                throw new Error(`not supported ID: ${id}`)
        }
        const gg = new Group(gid)
        return {
            id,
            gg,
            hash,
            blindedSize: 1 + gg.size,
            evaluationSize: 1 + gg.size,
            blindSize: gg.size
        }
    }

    static getContextString(id: OprfID): Uint8Array {
        Oprf.validateID(id)
        return joinAll([new TextEncoder().encode(Oprf.version), new Uint8Array([Oprf.mode, 0, id])])
    }

    static getHashToGroupDST(id: OprfID): Uint8Array {
        return joinAll([new TextEncoder().encode('HashToGroup-'), Oprf.getContextString(id)])
    }

    static getHashToScalarDST(id: OprfID): Uint8Array {
        return joinAll([new TextEncoder().encode('HashToScalar-'), Oprf.getContextString(id)])
    }

    static getDeriveKeyPairDST(id: OprfID): Uint8Array {
        return joinAll([new TextEncoder().encode('DeriveKeyPair'), Oprf.getContextString(id)])
    }

    protected async coreFinalize(
        input: Uint8Array,
        unblindedElement: Uint8Array
    ): Promise<Uint8Array> {
        const hashInput = joinAll([
            to16bits(input.length),
            input,
            to16bits(unblindedElement.length),
            unblindedElement,
            new TextEncoder().encode('Finalize')
        ])
        return new Uint8Array(await crypto.subtle.digest(this.params.hash, hashInput))
    }
}
