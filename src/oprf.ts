// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { DLEQParams, DLEQProof } from './dleq.js'
import { Elt, Group, GroupID, Scalar } from './group.js'
import { checkSize, fromU16LenPrefix, joinAll, toU16LenPrefix } from './util.js'

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
            hasInfo = toU16LenPrefix(info)
        }

        const hashInput = joinAll([
            ...toU16LenPrefix(input),
            ...hasInfo,
            ...toU16LenPrefix(element),
            new TextEncoder().encode(Oprf.LABELS.FinalizeDST)
        ])
        return new Uint8Array(await crypto.subtle.digest(this.hash, hashInput))
    }

    protected scalarFromInfo(info: Uint8Array): Promise<Scalar> {
        if (info.length >= 1 << 16) {
            throw new Error('invalid info length')
        }
        const te = new TextEncoder()
        const framedInfo = joinAll([te.encode('Info'), ...toU16LenPrefix(info)])
        return this.gg.hashToScalar(framedInfo, this.getDST(Oprf.LABELS.HashToScalarDST))
    }
}

export class Evaluation {
    constructor(public readonly evaluated: Elt, public readonly proof?: DLEQProof) {}

    serialize(): Uint8Array {
        return joinAll([
            this.evaluated.serialize(true),
            Uint8Array.from([this.proof ? 1 : 0]),
            this.proof ? this.proof.serialize() : new Uint8Array()
        ])
    }

    isEqual(e: Evaluation): boolean {
        if ((this.proof && !e.proof) || (!this.proof && e.proof)) {
            return false
        }
        let res = this.evaluated.isEqual(e.evaluated)
        if (this.proof && e.proof) {
            res &&= this.proof.isEqual(e.proof)
        }
        return res
    }

    static size(params: DLEQParams): number {
        return Elt.size(params.gg) + 1
    }

    static deserialize(params: DLEQParams, bytes: Uint8Array): Evaluation {
        checkSize(bytes, Evaluation, params)
        const eltSize = Elt.size(params.gg)
        const evaluated = Elt.deserialize(params.gg, bytes.subarray(0, eltSize))
        let proof: DLEQProof | undefined
        if (bytes[eltSize as number] === 1) {
            const prSize = DLEQProof.size(params)
            proof = DLEQProof.deserialize(params, bytes.subarray(1 + eltSize, 1 + eltSize + prSize))
        }
        return new Evaluation(evaluated, proof)
    }
}

export class EvaluationRequest {
    constructor(public readonly blinded: Elt) {}

    serialize(): Uint8Array {
        return this.blinded.serialize(true)
    }

    isEqual(e: EvaluationRequest): boolean {
        return this.blinded.isEqual(e.blinded)
    }

    static size(g: Group): number {
        return Elt.size(g)
    }

    static deserialize(g: Group, bytes: Uint8Array): EvaluationRequest {
        checkSize(bytes, EvaluationRequest, g)
        return new EvaluationRequest(Elt.deserialize(g, bytes))
    }
}

export class FinalizeData {
    constructor(
        public readonly input: Uint8Array,
        public readonly blind: Scalar,
        public readonly evalReq: EvaluationRequest
    ) {}

    serialize(): Uint8Array {
        return joinAll([
            ...toU16LenPrefix(this.input),
            this.blind.serialize(),
            this.evalReq.serialize()
        ])
    }
    isEqual(f: FinalizeData): boolean {
        return (
            this.input.toString() === f.input.toString() &&
            this.blind.isEqual(f.blind) &&
            this.evalReq.isEqual(f.evalReq)
        )
    }
    static size(g: Group): number {
        return 2 + Scalar.size(g) + EvaluationRequest.size(g)
    }

    static deserialize(g: Group, bytes: Uint8Array): FinalizeData {
        checkSize(bytes, FinalizeData, g)
        const { head: input, tail } = fromU16LenPrefix(bytes)
        const scSize = Scalar.size(g)
        const erSize = EvaluationRequest.size(g)
        const blind = Scalar.deserialize(g, tail.subarray(0, scSize))
        const evalReq = EvaluationRequest.deserialize(g, tail.subarray(scSize, scSize + erSize))
        return new FinalizeData(input, blind, evalReq)
    }
}
