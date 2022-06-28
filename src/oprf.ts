// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { DLEQParams, DLEQProof } from './dleq.js'
import { Elt, Group, GroupID, Scalar } from './group.js'
import {
    fromU16LenPrefixClass,
    fromU16LenPrefixUint8Array,
    joinAll,
    toU16LenPrefix,
    toU16LenPrefixClass,
    toU16LenPrefixUint8Array
} from './util.js'

export type ModeID = typeof Oprf.Mode[keyof typeof Oprf.Mode]
export type SuiteID = typeof Oprf.Suite[keyof typeof Oprf.Suite]

function assertNever(name: string, x: unknown): never {
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
        Version: 'VOPRF10-',
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
        const framedInfo = joinAll([te.encode(Oprf.LABELS.InfoLabel), ...toU16LenPrefix(info)])
        return this.gg.hashToScalar(framedInfo, this.getDST(Oprf.LABELS.HashToScalarDST))
    }
}

export class Evaluation {
    constructor(
        public readonly mode: ModeID,
        public readonly evaluated: Array<Elt>,
        public readonly proof?: DLEQProof
    ) {}

    serialize(): Uint8Array {
        let proofBytes = new Uint8Array()
        if (this.proof && (this.mode == Oprf.Mode.VOPRF || this.mode == Oprf.Mode.POPRF)) {
            proofBytes = this.proof.serialize()
        }

        return joinAll([
            ...toU16LenPrefixClass(this.evaluated),
            Uint8Array.from([this.mode]),
            proofBytes
        ])
    }

    isEqual(e: Evaluation): boolean {
        if (this.mode !== e.mode || (this.proof && !e.proof) || (!this.proof && e.proof)) {
            return false
        }
        let res = this.evaluated.every((x, i) => x.isEqual(e.evaluated[i as number]))
        if (this.proof && e.proof) {
            res &&= this.proof.isEqual(e.proof)
        }
        return res
    }

    static deserialize(params: DLEQParams, bytes: Uint8Array): Evaluation {
        const { head: evalList, tail } = fromU16LenPrefixClass(Elt, params.gg, bytes)
        let proof: DLEQProof | undefined
        const prSize = DLEQProof.size(params)
        const proofBytes = tail.subarray(1, 1 + prSize)
        const mode = tail[0]
        switch (mode) {
            case Oprf.Mode.OPRF: // no proof exists.
                break
            case Oprf.Mode.VOPRF:
            case Oprf.Mode.POPRF:
                proof = DLEQProof.deserialize(params, proofBytes)
                break
            default:
                assertNever('Oprf.Mode', mode)
        }
        return new Evaluation(mode, evalList, proof)
    }
}

export class EvaluationRequest {
    constructor(public readonly blinded: Array<Elt>) {}

    serialize(): Uint8Array {
        return joinAll(toU16LenPrefixClass(this.blinded))
    }

    isEqual(e: EvaluationRequest): boolean {
        return this.blinded.every((x, i) => x.isEqual(e.blinded[i as number]))
    }

    static deserialize(g: Group, bytes: Uint8Array): EvaluationRequest {
        const { head: blindedList } = fromU16LenPrefixClass(Elt, g, bytes)
        return new EvaluationRequest(blindedList)
    }
}

export class FinalizeData {
    constructor(
        public readonly inputs: Array<Uint8Array>,
        public readonly blinds: Array<Scalar>,
        public readonly evalReq: EvaluationRequest
    ) {}

    serialize(): Uint8Array {
        return joinAll([
            ...toU16LenPrefixUint8Array(this.inputs),
            ...toU16LenPrefixClass(this.blinds),
            this.evalReq.serialize()
        ])
    }

    isEqual(f: FinalizeData): boolean {
        return (
            this.inputs.every((x, i) => x.toString() === f.inputs[i as number].toString()) &&
            this.blinds.every((x, i) => x.isEqual(f.blinds[i as number])) &&
            this.evalReq.isEqual(f.evalReq)
        )
    }

    static deserialize(g: Group, bytes: Uint8Array): FinalizeData {
        const { head: inputs, tail: t0 } = fromU16LenPrefixUint8Array(bytes)
        const { head: blinds, tail: t1 } = fromU16LenPrefixClass(Scalar, g, t0)
        const evalReq = EvaluationRequest.deserialize(g, t1)
        return new FinalizeData(inputs, blinds, evalReq)
    }
}
