// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { type DLEQParams, DLEQProof } from './dleq.js'
import {
    type Elt,
    GROUP,
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
import type { CryptoProvider, HashID } from './cryptoTypes.js'
import { LABELS, MODE, SUITE } from './consts.js'
import {
    type CryptoProviderArg,
    getCrypto,
    getSuiteGroup,
    getCryptoProvider,
    setCryptoProvider
} from './cryptoImpl.js'

export type ModeID = (typeof Oprf.Mode)[keyof typeof Oprf.Mode]
export type SuiteID = (typeof Oprf.Suite)[keyof typeof Oprf.Suite]

function assertNever(name: string, x: unknown): never {
    throw new Error(`unexpected ${name} identifier: ${x}`)
}

export function getOprfParams(
    id: string
): readonly [suite: SuiteID, group: GroupID, hash: HashID, size: number] {
    switch (id) {
        case Oprf.Suite.P256_SHA256:
            return [Oprf.Suite.P256_SHA256, GROUP.P256, 'SHA-256', 32]
        case Oprf.Suite.P384_SHA384:
            return [Oprf.Suite.P384_SHA384, GROUP.P384, 'SHA-384', 48]
        case Oprf.Suite.P521_SHA512:
            return [Oprf.Suite.P521_SHA512, GROUP.P521, 'SHA-512', 64]
        case Oprf.Suite.RISTRETTO255_SHA512:
            return [Oprf.Suite.RISTRETTO255_SHA512, GROUP.RISTRETTO255, 'SHA-512', 64]
        case Oprf.Suite.DECAF448_SHAKE256:
            return [Oprf.Suite.DECAF448_SHAKE256, GROUP.DECAF448, 'SHAKE256', 64]
        default:
            assertNever('Oprf.Suite', id)
    }
}

// testing helper
export function getSupportedSuites(g: GroupCons): Array<SuiteID> {
    return Object.values(Oprf.Suite).filter((v) => g.supportedGroups.includes(getOprfParams(v)[1]))
}

export abstract class Oprf {
    static set Crypto(provider: CryptoProvider) {
        setCryptoProvider(provider)
    }

    static get Crypto(): CryptoProvider {
        return getCryptoProvider()
    }

    static Mode = MODE
    static Suite = SUITE
    static LABELS = LABELS

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

    static getGroup(suite: SuiteID, ...arg: CryptoProviderArg): Group {
        return getSuiteGroup(suite, arg)
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

    readonly mode: ModeID
    readonly suite: SuiteID
    readonly hashID: HashID

    readonly group: Group
    readonly crypto: CryptoProvider

    protected constructor(mode: ModeID, suite: SuiteID, ...arg: CryptoProviderArg) {
        const [ID, gid, hash] = getOprfParams(suite)
        this.crypto = getCrypto(arg)
        this.group = this.crypto.Group.get(gid)
        this.suite = ID
        this.hashID = hash
        this.mode = Oprf.validateMode(mode)
    }

    protected getDLEQParams(): DLEQParams {
        const EMPTY_DST = ''
        return { group: this.group.id, hash: this.hashID, dst: this.getDST(EMPTY_DST) }
    }

    protected getDST(name: string): Uint8Array {
        return Oprf.getDST(this.mode, this.suite, name)
    }

    protected async coreFinalize(
        input: Uint8Array,
        issuedElement: Uint8Array,
        info: Uint8Array
    ): Promise<Uint8Array> {
        let hasInfo: Uint8Array[] = []
        if (this.mode === Oprf.Mode.POPRF) {
            hasInfo = toU16LenPrefix(info)
        }

        const hashInput = joinAll([
            ...toU16LenPrefix(input),
            ...hasInfo,
            ...toU16LenPrefix(issuedElement),
            new TextEncoder().encode(Oprf.LABELS.FinalizeDST)
        ])
        return await this.crypto.hash(this.hashID, hashInput)
    }

    protected scalarFromInfo(info: Uint8Array): Promise<Scalar> {
        if (info.length >= 1 << 16) {
            throw new Error('invalid info length')
        }
        const te = new TextEncoder()
        const framedInfo = joinAll([te.encode(Oprf.LABELS.InfoLabel), ...toU16LenPrefix(info)])
        return this.group.hashToScalar(framedInfo, this.getDST(Oprf.LABELS.HashToScalarDST))
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
        let res = this.evaluated.every((x, i) => x.isEqual(e.evaluated[i]))
        if (this.proof && e.proof) {
            res &&= this.proof.isEqual(e.proof)
        }
        return res
    }

    static deserialize(suite: SuiteID, bytes: Uint8Array, ...arg: CryptoProviderArg): Evaluation {
        const group = getSuiteGroup(suite, arg)

        const { head: evalList, tail } = fromU16LenPrefixDes(group.eltDes, bytes)
        let proof: DLEQProof | undefined
        const proofSize = DLEQProof.size(group)
        const proofBytes = tail.subarray(1, 1 + proofSize)
        const mode = tail[0]
        switch (mode) {
            case Oprf.Mode.OPRF: // no proof exists.
                break
            case Oprf.Mode.VOPRF:
            case Oprf.Mode.POPRF:
                proof = DLEQProof.deserialize(group.id, proofBytes, ...arg)
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
        return this.blinded.every((x, i) => x.isEqual(e.blinded[i]))
    }

    static deserialize(
        suite: SuiteID,
        bytes: Uint8Array,
        ...arg: CryptoProviderArg
    ): EvaluationRequest {
        const g = getSuiteGroup(suite, arg)
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
            this.inputs.every((x, i) => x.toString() === f.inputs[i].toString()) &&
            this.blinds.every((x, i) => x.isEqual(f.blinds[i])) &&
            this.evalReq.isEqual(f.evalReq)
        )
    }

    static deserialize(suite: SuiteID, bytes: Uint8Array, ...arg: CryptoProviderArg): FinalizeData {
        const g = getSuiteGroup(suite, arg)
        const { head: inputs, tail: t0 } = fromU16LenPrefixUint8Array(bytes)
        const { head: blinds, tail: t1 } = fromU16LenPrefixDes(g.scalarDes, t0)
        const evalReq = EvaluationRequest.deserialize(suite, t1, ...arg)
        return new FinalizeData(inputs, blinds, evalReq)
    }
}
