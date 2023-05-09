// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause
//
// Implementation of batched discrete log equivalents proofs (DLEQ) as
// described in https://www.ietf.org/id/draft-irtf-cfrg-voprf-09.html#name-discrete-log-equivalence-pr.
import { Elt, Group, Scalar } from './groupTypes.js'
import { checkSize, joinAll, to16bits, toU16LenPrefix } from './util.js'

export interface DLEQParams {
    readonly gg: Group
    readonly hash: string
    readonly dst: string
}

const LABELS = {
    Seed: 'Seed-',
    Challenge: 'Challenge',
    Composite: 'Composite',
    HashToScalar: 'HashToScalar-'
} as const

// computeComposites implements ComputeComposites and ComputeCompositiesFast
// functions from https://www.ietf.org/id/draft-irtf-cfrg-voprf-09.html#name-discrete-log-equivalence-pr.
async function computeComposites(
    params: DLEQParams,
    b: Elt,
    cd: Array<[Elt, Elt]>,
    key?: Scalar
): Promise<{ M: Elt; Z: Elt }> {
    const te = new TextEncoder()
    const Bm = b.serialize()
    const seedDST = te.encode(LABELS.Seed + params.dst)
    const h1Input = joinAll([...toU16LenPrefix(Bm), ...toU16LenPrefix(seedDST)])
    const seed = new Uint8Array(await crypto.subtle.digest(params.hash, h1Input))

    const compositeLabel = te.encode(LABELS.Composite)
    const h2sDST = te.encode(LABELS.HashToScalar + params.dst)
    let M = params.gg.identity()
    let Z = params.gg.identity()
    let i = 0
    for (const [c, d] of cd) {
        const Ci = c.serialize()
        const Di = d.serialize()

        const h2Input = joinAll([
            ...toU16LenPrefix(seed),
            to16bits(i++),
            ...toU16LenPrefix(Ci),
            ...toU16LenPrefix(Di),
            compositeLabel
        ])
        const di = await params.gg.hashToScalar(h2Input, h2sDST)
        M = M.add(c.mul(di))

        if (!key) {
            Z = Z.add(d.mul(di))
        }
    }

    if (key) {
        Z = M.mul(key)
    }

    return { M, Z }
}

// challenge implements the shared subprocedure for generating a challenge
// used by the GenerateProof and VerifyProof functions
// from https://www.ietf.org/id/draft-irtf-cfrg-voprf-09.html#name-discrete-log-equivalence-pr
// to generate a challenge from the input elements. The point arguments
// correspond to [B, M, Z, t2, t3] from the specification.
function challenge(params: DLEQParams, points: [Elt, Elt, Elt, Elt, Elt]): Promise<Scalar> {
    let h2Input = new Uint8Array()
    for (const p of points) {
        const P = p.serialize()
        h2Input = joinAll([h2Input, ...toU16LenPrefix(P)])
    }
    const te = new TextEncoder()
    h2Input = joinAll([h2Input, te.encode(LABELS.Challenge)])
    const h2sDST = te.encode(LABELS.HashToScalar + params.dst)
    return params.gg.hashToScalar(h2Input, h2sDST)
}

export class DLEQProof {
    constructor(
        public readonly params: Required<DLEQParams>,
        public readonly c: Scalar,
        public readonly s: Scalar
    ) {}

    verify(p0: [Elt, Elt], p1: [Elt, Elt]): Promise<boolean> {
        return this.verify_batch(p0, [p1])
    }

    // verify_batch implements the VerifyProof function
    // from https://www.ietf.org/id/draft-irtf-cfrg-voprf-09.html#name-discrete-log-equivalence-pr.
    // The argument p0 corresponds to the elements A, B, and the argument p1s
    // corresponds to the arrays of elements C and D from the specification.
    async verify_batch(p0: [Elt, Elt], p1s: Array<[Elt, Elt]>): Promise<boolean> {
        const { M, Z } = await computeComposites(this.params, p0[1], p1s)
        const t2 = p0[0].mul2(this.s, p0[1], this.c)
        const t3 = M.mul2(this.s, Z, this.c)
        const c = await challenge(this.params, [p0[1], M, Z, t2, t3])
        return this.c.isEqual(c)
    }

    isEqual(p: DLEQProof): boolean {
        return (
            this.params.dst === p.params.dst &&
            this.params.gg.id === p.params.gg.id &&
            this.params.hash === p.params.hash &&
            this.c.isEqual(p.c) &&
            this.s.isEqual(p.s)
        )
    }

    serialize(): Uint8Array {
        return joinAll([this.c.serialize(), this.s.serialize()])
    }

    static size(params: DLEQParams): number {
        return 2 * params.gg.scalarSize()
    }

    static deserialize(params: Required<DLEQParams>, bytes: Uint8Array): DLEQProof {
        checkSize(bytes, DLEQProof, params)
        const group = params.gg
        const n = group.scalarSize()
        const c = group.desScalar(bytes.subarray(0, n))
        const s = group.desScalar(bytes.subarray(n, 2 * n))
        return new DLEQProof(params, c, s)
    }
}

export class DLEQProver {
    constructor(public readonly params: DLEQParams) {}

    prove(k: Scalar, p0: [Elt, Elt], p1: [Elt, Elt], r?: Scalar): Promise<DLEQProof> {
        return this.prove_batch(k, p0, [p1], r)
    }

    // prove_batch implements the GenerateProof function
    // from https://www.ietf.org/id/draft-irtf-cfrg-voprf-09.html#name-discrete-log-equivalence-pr.
    // The argument p0 corresponds to the elements A, B, and the argument p1s
    // corresponds to the arrays of elements C and D from the specification.
    async prove_batch(
        key: Scalar,
        p0: [Elt, Elt],
        p1s: Array<[Elt, Elt]>,
        r?: Scalar
    ): Promise<DLEQProof> {
        const rnd = r ? r : await this.params.gg.randomScalar()
        const { M, Z } = await computeComposites(this.params, p0[1], p1s, key)
        const t2 = p0[0].mul(rnd)
        const t3 = M.mul(rnd)
        const c = await challenge(this.params, [p0[1], M, Z, t2, t3])
        const s = rnd.sub(c.mul(key))
        return new DLEQProof(this.params, c, s)
    }
}
