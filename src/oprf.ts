// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { type DLEQParams, DLEQProof } from './dleq.js'
import {
    Groups,
    type Elt,
    type Group,
    type GroupCons,
    type GroupID,
    type Scalar
} from './groupTypes.js'

import {
    fromU16LenPrefixDes,
    fromU16LenPrefixUint8Array,
    joinAll,
    toU16LenPrefix,
    toU16LenPrefixClass,
    toU16LenPrefixUint8Array
} from './util.js'
import type { HashID } from './cryptoTypes.js'
import { CryptoImpl } from './cryptoImpl.js'

export type ModeID = (typeof Oprf.Mode)[keyof typeof Oprf.Mode]
export type SuiteID = (typeof Oprf.Suite)[keyof typeof Oprf.Suite]

function assertNever(name: string, x: unknown): never {
    throw new Error(`unexpected ${name} identifier: ${x}`)
}

function getOprfParams(id: string): readonly [SuiteID, GroupID, HashID, number] {
    switch (id) {
        case Oprf.Suite.P256_SHA256:
            return [Oprf.Suite.P256_SHA256, Groups.P256, 'SHA-256', 32]
        case Oprf.Suite.P384_SHA384:
            return [Oprf.Suite.P384_SHA384, Groups.P384, 'SHA-384', 48]
        case Oprf.Suite.P521_SHA512:
            return [Oprf.Suite.P521_SHA512, Groups.P521, 'SHA-512', 64]
        case Oprf.Suite.RISTRETTO255_SHA512:
            return [Oprf.Suite.RISTRETTO255_SHA512, Groups.RISTRETTO255, 'SHA-512', 64]
        case Oprf.Suite.DECAF448_SHAKE256:
            return [Oprf.Suite.DECAF448_SHAKE256, Groups.DECAF448, 'SHAKE256', 64]
        default:
            assertNever('Oprf.Suite', id)
    }
}

// testing helper
export function getSupportedSuites(g: GroupCons): Array<SuiteID> {
    return Object.values(Oprf.Suite).filter((v) => g.supportedGroups.includes(getOprfParams(v)[1]))
}

export abstract class Oprf {
    static Mode = {
        OPRF: 0,
        VOPRF: 1,
        POPRF: 2
    } as const

    static Suite = {
        P256_SHA256: 'P256-SHA256',
        P384_SHA384: 'P384-SHA384',
        P521_SHA512: 'P521-SHA512',
        RISTRETTO255_SHA512: 'ristretto255-SHA512',
        DECAF448_SHAKE256: 'decaf448-SHAKE256'
    } as const

    static LABELS = {
        Version: 'OPRFV1-',
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

    static getGroup(suite: SuiteID): Group {
        return CryptoImpl.Group.fromID(getOprfParams(suite)[1])
    }

    static getHash(suite: SuiteID): HashID {
        return getOprfParams(suite)[2]
    }

    static getOprfSize(suite: SuiteID): number {
        return getOprfParams(suite)[3]
    }

    static getDST(mode: ModeID, suite: SuiteID, name: string): Uint8Array {
        const m = Oprf.validateMode(mode)
        const te = new TextEncoder()
        return joinAll([
            te.encode(name + Oprf.LABELS.Version),
            Uint8Array.of(m),
            te.encode('-' + suite)
        ])
    }

    readonly modeID: ModeID
    readonly suiteID: SuiteID
    readonly gg: Group
    readonly hashID: HashID

    constructor(mode: ModeID, suite: SuiteID) {
        const [ID, gid, hash] = getOprfParams(suite)
        this.suiteID = ID
        this.gg = CryptoImpl.Group.fromID(gid)
        this.hashID = hash
        this.modeID = Oprf.validateMode(mode)
    }

    protected getDST(name: string): Uint8Array {
        return Oprf.getDST(this.modeID, this.suiteID, name)
    }

    protected async coreFinalize(
        input: Uint8Array,
        issuedElement: Uint8Array,
        info: Uint8Array
    ): Promise<Uint8Array> {
        let hasInfo: Uint8Array[] = []
        if (this.modeID === Oprf.Mode.POPRF) {
            hasInfo = toU16LenPrefix(info)
        }

        const hashInput = joinAll([
            ...toU16LenPrefix(input),
            ...hasInfo,
            ...toU16LenPrefix(issuedElement),
            new TextEncoder().encode(Oprf.LABELS.FinalizeDST)
        ])
        return await CryptoImpl.hash(this.hashID, hashInput)
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
        const { head: evalList, tail } = fromU16LenPrefixDes(params.gg.eltDes, bytes)
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
        const { head: blindedList } = fromU16LenPrefixDes(g.eltDes, bytes)
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
        const { head: blinds, tail: t1 } = fromU16LenPrefixDes(g.scalarDes, t0)
        const evalReq = EvaluationRequest.deserialize(g, t1)
        return new FinalizeData(inputs, blinds, evalReq)
    }
}
