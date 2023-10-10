// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause
//
// Implementation of batched discrete log equivalents proofs (DLEQ) as
// described in https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#name-discrete-logarithm-equivale
import type { HashID } from './cryptoTypes.js'
import type { Elt, Group, Scalar } from './groupTypes.js'
import { checkSize, joinAll, to16bits, toU16LenPrefix } from './util.js'

export interface DLEQParams {
    readonly group: Group
    readonly dst: Uint8Array
    readonly hashID: HashID
    hash(hashID: HashID, input: Uint8Array): Promise<Uint8Array>
}

const LABELS = {
    Seed: 'Seed-',
    Challenge: 'Challenge',
    Composite: 'Composite',
    HashToScalar: 'HashToScalar-'
} as const

// computeComposites implements ComputeComposites and ComputeCompositiesFast
// functions from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#name-discrete-logarithm-equivale
async function computeComposites(
    params: DLEQParams,
    b: Elt,
    cd: Array<[Elt, Elt]>,
    key?: Scalar
): Promise<{ M: Elt; Z: Elt }> {
    const te = new TextEncoder()
    const Bm = b.serialize()
    const seedDST = joinAll([te.encode(LABELS.Seed), params.dst])
    const h1Input = joinAll([...toU16LenPrefix(Bm), ...toU16LenPrefix(seedDST)])
    const seed = await params.hash(params.hashID, h1Input)

    const compositeLabel = te.encode(LABELS.Composite)
    const h2sDST = joinAll([te.encode(LABELS.HashToScalar), params.dst])
    let M = params.group.identity()
    let Z = params.group.identity()
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
        const di = await params.group.hashToScalar(h2Input, h2sDST)
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
// from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#name-discrete-logarithm-equivale
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
    const h2sDST = joinAll([te.encode(LABELS.HashToScalar), params.dst])
    return params.group.hashToScalar(h2Input, h2sDST)
}

export class DLEQProof {
    constructor(
        public readonly c: Scalar,
        public readonly s: Scalar
    ) {}

    isEqual(p: DLEQProof): boolean {
        return this.c.isEqual(p.c) && this.s.isEqual(p.s)
    }

    serialize(): Uint8Array {
        return joinAll([this.c.serialize(), this.s.serialize()])
    }

    static size(g: Group): number {
        return 2 * g.scalarSize()
    }

    static deserialize(g: Group, bytes: Uint8Array): DLEQProof {
        checkSize(bytes, DLEQProof, g)
        const n = g.scalarSize()
        const c = g.desScalar(bytes.subarray(0, n))
        const s = g.desScalar(bytes.subarray(n, 2 * n))
        return new DLEQProof(c, s)
    }
}

export class DLEQVerifier {
    constructor(public readonly params: DLEQParams) {}

    verify(p0: [Elt, Elt], p1: [Elt, Elt], proof: DLEQProof): Promise<boolean> {
        return this.verify_batch(p0, [p1], proof)
    }

    // verify_batch implements the VerifyProof function
    // from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#name-discrete-logarithm-equivale
    // The argument p0 corresponds to the elements A, B, and the argument p1s
    // corresponds to the arrays of elements C and D from the specification.
    async verify_batch(p0: [Elt, Elt], p1s: Array<[Elt, Elt]>, proof: DLEQProof): Promise<boolean> {
        const { M, Z } = await computeComposites(this.params, p0[1], p1s)
        const t2 = p0[0].mul2(proof.s, p0[1], proof.c)
        const t3 = M.mul2(proof.s, Z, proof.c)
        const c = await challenge(this.params, [p0[1], M, Z, t2, t3])
        return proof.c.isEqual(c)
    }
}

export class DLEQProver extends DLEQVerifier {
    prove(k: Scalar, p0: [Elt, Elt], p1: [Elt, Elt], r?: Scalar): Promise<DLEQProof> {
        return this.prove_batch(k, p0, [p1], r)
    }

    randomScalar(): Promise<Scalar> {
        return this.params.group.randomScalar()
    }

    // prove_batch implements the GenerateProof function
    // from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#name-discrete-logarithm-equivale
    // The argument p0 corresponds to the elements A, B, and the argument p1s
    // corresponds to the arrays of elements C and D from the specification.
    async prove_batch(
        key: Scalar,
        p0: [Elt, Elt],
        p1s: Array<[Elt, Elt]>,
        r?: Scalar
    ): Promise<DLEQProof> {
        const rnd = r ? r : await this.randomScalar()
        const { M, Z } = await computeComposites(this.params, p0[1], p1s, key)
        const t2 = p0[0].mul(rnd)
        const t3 = M.mul(rnd)
        const c = await challenge(this.params, [p0[1], M, Z, t2, t3])
        const s = rnd.sub(c.mul(key))
        return new DLEQProof(c, s)
    }
}
