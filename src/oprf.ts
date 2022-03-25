// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { Group, GroupID, Scalar } from './group.js'
import { joinAll, to16bits } from './util.js'

import { DLEQProof } from './dleq.js'

export type ModeID = typeof Oprf.Mode[keyof typeof Oprf.Mode]
export type SuiteID = typeof Oprf.Suite[keyof typeof Oprf.Suite]

function assertNever(name: string, x: never): never {
    throw new Error(`unexpected ${name} identifier: ${x}`)
}

export abstract class Oprf {
    static Mode = {
        OPRF: 0,
        VOPRF: 1,
        POPRF: 2
    } as const

    static Suite = {
        P256_SHA256: 3,
        P384_SHA384: 4,
        P521_SHA512: 5
    } as const

    static LABELS = {
        Version: 'VOPRF09-',
        FinalizeDST: 'Finalize',
        HashToGroupDST: 'HashToGroup-',
        HashToScalarDST: 'HashToScalar-',
        DeriveKeyPairDST: 'DeriveKeyPair',
        InfoLabel: 'Info'
    } as const

    private static validateMode(m: ModeID): ModeID {
        switch (m) {
            case Oprf.Mode.OPRF:
            case Oprf.Mode.VOPRF:
            case Oprf.Mode.POPRF:
                return m
            default:
                assertNever('Oprf.Mode', m)
        }
    }
    private static getParams(id: SuiteID): [SuiteID, GroupID, string, number] {
        switch (id) {
            case Oprf.Suite.P256_SHA256:
                return [id, Group.ID.P256, 'SHA-256', 32]
            case Oprf.Suite.P384_SHA384:
                return [id, Group.ID.P384, 'SHA-384', 48]
            case Oprf.Suite.P521_SHA512:
                return [id, Group.ID.P521, 'SHA-512', 64]
            default:
                assertNever('Oprf.Suite', id)
        }
    }
    static getGroup(suite: SuiteID): Group {
        return new Group(Oprf.getParams(suite)[1])
    }
    static getHash(suite: SuiteID): string {
        return Oprf.getParams(suite)[2]
    }
    static getOprfSize(suite: SuiteID): number {
        return Oprf.getParams(suite)[3]
    }
    static getDST(mode: ModeID, suite: SuiteID, name: string): Uint8Array {
        const m = Oprf.validateMode(mode)
        const s = Oprf.getParams(suite)[0]
        return joinAll([
            new TextEncoder().encode(name + Oprf.LABELS.Version),
            new Uint8Array([m, 0, s])
        ])
    }

    readonly mode: ModeID
    readonly ID: SuiteID
    readonly gg: Group
    readonly hash: string

    constructor(mode: ModeID, suite: SuiteID) {
        const [ID, gid, hash] = Oprf.getParams(suite)
        this.ID = ID
        this.gg = new Group(gid)
        this.hash = hash
        this.mode = Oprf.validateMode(mode)
    }

    protected getDST(name: string): Uint8Array {
        return Oprf.getDST(this.mode, this.ID, name)
    }

    protected async coreFinalize(
        input: Uint8Array,
        element: Uint8Array,
        info: Uint8Array
    ): Promise<Uint8Array> {
        let hasInfo: Uint8Array[] = []
        if (this.mode === Oprf.Mode.POPRF) {
            hasInfo = [to16bits(info.length), info]
        }

        const hashInput = joinAll([
            to16bits(input.length),
            input,
            ...hasInfo,
            to16bits(element.length),
            element,
            new TextEncoder().encode(Oprf.LABELS.FinalizeDST)
        ])
        return new Uint8Array(await crypto.subtle.digest(this.hash, hashInput))
    }

    protected scalarFromInfo(info: Uint8Array): Promise<Scalar> {
        if (info.length >= 1 << 16) {
            throw new Error('invalid info length')
        }
        const te = new TextEncoder()
        const framedInfo = joinAll([te.encode('Info'), to16bits(info.length), info])
        return this.gg.hashToScalar(framedInfo, this.getDST(Oprf.LABELS.HashToScalarDST))
    }
}

export class Blind extends Uint8Array {
    readonly _BlindBrand = ''
}
export class Blinded extends Uint8Array {
    readonly _BlindedBrand = ''
}
export class Evaluated extends Uint8Array {
    readonly _EvaluatedBrand = ''
}

export class Evaluation {
    constructor(public readonly element: Evaluated, public readonly proof?: DLEQProof) {}
}

export class EvaluationRequest {
    constructor(public readonly blinded: Blinded) {}
}

export class FinalizeData {
    constructor(
        public readonly input: Uint8Array,
        public readonly blind: Blind,
        public readonly evalReq: EvaluationRequest
    ) {}
}
