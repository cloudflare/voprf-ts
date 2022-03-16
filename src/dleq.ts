// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { Elt, Group, Scalar } from './group.js'
import { joinAll, to16bits } from './util.js'

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

async function computeComposites(
    params: DLEQParams,
    b: Elt,
    cd: Array<[Elt, Elt]>,
    key?: Scalar
): Promise<{ M: Elt; Z: Elt }> {
    const te = new TextEncoder()
    const Bm = params.gg.serialize(b)
    const seedDST = te.encode(LABELS.Seed + params.dst)
    const h1Input = joinAll([to16bits(Bm.length), Bm, to16bits(seedDST.length), seedDST])
    const seed = new Uint8Array(await crypto.subtle.digest(params.hash, h1Input))

    const compositeLabel = te.encode(LABELS.Composite)
    const h2sDST = te.encode(LABELS.HashToScalar + params.dst)
    let M = params.gg.identity()
    let Z = params.gg.identity()
    let i = 0
    for (const [c, d] of cd) {
        const Ci = params.gg.serialize(c)
        const Di = params.gg.serialize(d)

        const h2Input = joinAll([
            to16bits(seed.length),
            seed,
            to16bits(i++),
            to16bits(Ci.length),
            Ci,
            to16bits(Di.length),
            Di,
            compositeLabel
        ])
        const di = await params.gg.hashToScalar(h2Input, h2sDST)
        M = Group.add(M, Group.mul(di, c))

        if (!key) {
            Z = Group.add(Z, Group.mul(di, d))
        }
    }

    if (key) {
        Z = Group.mul(key, M)
    }

    return { M, Z }
}

function challenge(params: DLEQParams, points: [Elt, Elt, Elt, Elt, Elt]): Promise<Scalar> {
    let h2Input = new Uint8Array()
    for (const p of points) {
        const P = params.gg.serialize(p)
        h2Input = joinAll([h2Input, to16bits(P.length), P])
    }
    const te = new TextEncoder()
    h2Input = joinAll([h2Input, te.encode(LABELS.Challenge)])
    const h2sDST = te.encode(LABELS.HashToScalar + params.dst)
    return params.gg.hashToScalar(h2Input, h2sDST)
}

export interface DLEQProof {
    readonly params: DLEQParams
    readonly c: Scalar
    readonly s: Scalar
    verify(p0: [Elt, Elt], p1: [Elt, Elt]): Promise<boolean>
    verify_batch(p0: [Elt, Elt], p1: Array<[Elt, Elt]>): Promise<boolean>
}

class dleqProof implements DLEQProof {
    constructor(
        public readonly params: DLEQParams,
        public readonly c: Scalar,
        public readonly s: Scalar
    ) {}

    verify(p0: [Elt, Elt], p1: [Elt, Elt]): Promise<boolean> {
        return this.verify_batch(p0, [p1])
    }

    async verify_batch(p0: [Elt, Elt], p1s: Array<[Elt, Elt]>): Promise<boolean> {
        const { M, Z } = await computeComposites(this.params, p0[1], p1s)
        const t2 = Group.add(Group.mul(this.s, p0[0]), Group.mul(this.c, p0[1]))
        const t3 = Group.add(Group.mul(this.s, M), Group.mul(this.c, Z))
        const c = await challenge(this.params, [p0[1], M, Z, t2, t3])
        return this.params.gg.equalScalar(this.c, c)
    }
}

export class DLEQProver {
    constructor(public readonly params: DLEQParams) {}

    prove(k: Scalar, p0: [Elt, Elt], p1: [Elt, Elt], r?: Scalar): Promise<DLEQProof> {
        return this.prove_batch(k, p0, [p1], r)
    }

    async prove_batch(
        key: Scalar,
        p0: [Elt, Elt],
        p1s: Array<[Elt, Elt]>,
        r?: Scalar
    ): Promise<DLEQProof> {
        const rnd = r ? r : await this.params.gg.randomScalar()
        const { M, Z } = await computeComposites(this.params, p0[1], p1s, key)
        const t2 = Group.mul(rnd, p0[0])
        const t3 = Group.mul(rnd, M)
        const c = await challenge(this.params, [p0[1], M, Z, t2, t3])
        const s = this.params.gg.subScalar(rnd, this.params.gg.mulScalar(c, key))
        return new dleqProof(this.params, c, s)
    }
}
