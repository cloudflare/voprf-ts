// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { checkSize } from './util.js'
import { sha256 } from '@noble/hashes/sha256'
import { sha384 } from '@noble/hashes/sha512'
import { sha512 } from '@noble/hashes/sha512'
import { P256, hashToCurve as hashToP256 } from '@noble/curves/p256'
import { P384, hashToCurve as hashToP384 } from '@noble/curves/p384'
import { P521, hashToCurve as hashToP521 } from '@noble/curves/p521'
import { Fp, Field } from '@noble/curves/abstract/modular'
import { bytesToNumberBE } from '@noble/curves/abstract/utils'
import { expand_message_xmd } from '@noble/curves/abstract/hash-to-curve'
import { ProjConstructor, ProjPointType } from '@noble/curves/abstract/weierstrass'
import { CHash } from '@noble/hashes/utils'

function errDeserialization(T: { name: string }) {
    return new Error(`group: deserialization of ${T.name} failed.`)
}
function errGroup(X: GroupID, Y: GroupID) {
    return new Error(`group: mismatch between groups ${X} and ${Y}.`)
}
function errBadGroup(X: string) {
    return new Error(`group: bad group name ${X}.`)
}

function compat(x: { g: Group }, y: { g: Group }): void | never {
    if (x.g.id !== y.g.id) throw errGroup(x.g.id, y.g.id)
}

export class Scalar {
    private readonly fp: Field<bigint>
    public readonly k: bigint

    private constructor(public readonly g: Group, k: bigint) {
        this.fp = getCurve(this.g.id).fp
        this.k = this.fp.create(k)
    }

    static new(g: Group): Scalar {
        return new Scalar(g, BigInt(0))
    }

    isEqual(s: Scalar): boolean {
        return this.k === s.k
    }

    isZero(): boolean {
        return this.k === BigInt(0)
    }

    add(s: Scalar): Scalar {
        compat(this, s)
        return new Scalar(this.g, this.fp.add(this.k, s.k))
    }

    sub(s: Scalar): Scalar {
        compat(this, s)
        return new Scalar(this.g, this.fp.sub(this.k, s.k))
    }

    mul(s: Scalar): Scalar {
        compat(this, s)
        return new Scalar(this.g, this.fp.mul(this.k, s.k))
    }

    inv(): Scalar {
        return new Scalar(this.g, this.fp.inv(this.k))
    }

    serialize(): Uint8Array {
        const k = this.fp.create(this.k)
        const ab = this.fp.toBytes(k)
        const unpaded = new Uint8Array(ab)
        const serScalar = new Uint8Array(this.g.size)
        serScalar.set(unpaded, this.g.size - unpaded.length)
        return serScalar
    }

    static size(g: Group): number {
        return g.size
    }

    static deserialize(g: Group, bytes: Uint8Array): Scalar {
        checkSize(bytes, Scalar, g)
        const array = bytes.subarray(0, g.size)
        const k = bytesToNumberBE(array)
        const fp = getCurve(g.id).fp
        if (k >= fp.ORDER) {
            throw errDeserialization(Scalar)
        }
        return new Scalar(g, k)
    }

    static async hash(g: Group, msg: Uint8Array, dst: Uint8Array): Promise<Scalar> {
        const { hash, L } = getHashParams(g.id)
        const s = expand_message_xmd(msg, dst, L, hash)
        return new Scalar(g, bytesToNumberBE(s))
    }
}
interface HashParams {
    hash: CHash
    L: number
}

function getHashParams(gid: GroupID): HashParams {
    switch (gid) {
        case Group.ID.P256:
            return { hash: sha256, L: 48 }
        case Group.ID.P384:
            return { hash: sha384, L: 72 }
        case Group.ID.P521:
            return { hash: sha512, L: 98 }
        default:
            throw errBadGroup(gid)
    }
}

export class Elt {
    private constructor(public readonly g: Group, private readonly p: ProjPointType<bigint>) {}

    static new(g: Group): Elt {
        return new Elt(g, getCurve(g.id).Point.ZERO)
    }
    static gen(g: Group): Elt {
        return new Elt(g, getCurve(g.id).Point.BASE)
    }

    isIdentity(): boolean {
        return this.p.equals(getCurve(this.g.id).Point.ZERO)
    }

    isEqual(a: Elt): boolean {
        compat(this, a)
        return this.p.equals(a.p)
    }

    neg(): Elt {
        return new Elt(this.g, this.p.negate())
    }
    add(a: Elt): Elt {
        compat(this, a)
        return new Elt(this.g, this.p.add(a.p))
    }
    mul(s: Scalar): Elt {
        compat(this, s)
        return new Elt(this.g, this.p.multiply(s.k))
    }
    mul2(k1: Scalar, a: Elt, k2: Scalar): Elt {
        compat(this, k1)
        compat(this, k2)
        compat(this, a)
        const el = this.p.multiplyAndAddUnsafe(a.p, k1.k, k2.k)
        if (!el) throw new Error('result is zero')
        return new Elt(this.g, el)
    }
    serialize(compressed = true): Uint8Array {
        if (this.p.equals(getCurve(this.g.id).Point.ZERO)) {
            return Uint8Array.from([0])
        }
        return this.p.toRawBytes(compressed)
    }

    // size returns the number of bytes of a non-zero element in compressed or uncompressed form.
    static size(g: Group, compressed = true): number {
        return 1 + (compressed ? g.size : g.size * 2)
    }

    private static deser(g: Group, bytes: Uint8Array): Elt {
        const curve = getCurve(g.id)
        const point = curve.Point.fromHex(bytes)
        point.assertValidity()
        return new Elt(g, point)
    }

    // Deserializes an element, handles both compressed and uncompressed forms.
    static deserialize(g: Group, bytes: Uint8Array): Elt {
        const len = bytes.length
        switch (true) {
            case len === 1 && bytes[0] === 0x00:
                return g.identity()
            case len === 1 + g.size && (bytes[0] === 0x02 || bytes[0] === 0x03):
                return Elt.deser(g, bytes)
            case len === 1 + 2 * g.size && bytes[0] === 0x04:
                return Elt.deser(g, bytes)
            default:
                throw errDeserialization(Elt)
        }
    }

    static async hash(g: Group, msg: Uint8Array, dst: Uint8Array): Promise<Elt> {
        const h2c = getCurve(g.id).h2c
        const DST = new TextDecoder().decode(dst)
        const p = h2c(msg, { DST }) as ProjPointType<bigint>
        return new Elt(g, p)
    }
}

export type GroupID = typeof Group.ID[keyof typeof Group.ID]

export class Group {
    static ID = {
        P256: 'P-256',
        P384: 'P-384',
        P521: 'P-521'
    } as const

    public readonly id: GroupID

    public readonly size: number

    constructor(gid: GroupID) {
        switch (gid) {
            case Group.ID.P256:
                this.size = 32
                break
            case Group.ID.P384:
                this.size = 48
                break
            case Group.ID.P521:
                this.size = 66
                break
            default:
                throw errBadGroup(gid)
        }
        this.id = gid
    }

    static getID(id: string): GroupID {
        switch (id) {
            case 'P-256':
                return Group.ID.P256
            case 'P-384':
                return Group.ID.P384
            case 'P-521':
                return Group.ID.P521
            default:
                throw errBadGroup(id)
        }
    }

    newScalar(): Scalar {
        return Scalar.new(this)
    }

    newElt(): Elt {
        return this.identity()
    }

    identity(): Elt {
        return Elt.new(this)
    }

    generator(): Elt {
        return Elt.gen(this)
    }

    mulGen(s: Scalar): Elt {
        return Elt.gen(this).mul(s)
    }

    randomScalar(): Promise<Scalar> {
        const msg = crypto.getRandomValues(new Uint8Array(this.size))
        return Scalar.hash(this, msg, new Uint8Array())
    }

    hashToGroup(msg: Uint8Array, dst: Uint8Array): Promise<Elt> {
        return Elt.hash(this, msg, dst)
    }

    hashToScalar(msg: Uint8Array, dst: Uint8Array): Promise<Scalar> {
        return Scalar.hash(this, msg, dst)
    }
}

type CurveDef = {
    fp: Field<bigint>
    Point: ProjConstructor<bigint>
    h2c: typeof hashToP256
}
const curves: Record<GroupID, CurveDef> = {
    [Group.ID.P256]: { fp: Fp(P256.CURVE.n), Point: P256.ProjectivePoint, h2c: hashToP256 },
    [Group.ID.P384]: { fp: Fp(P384.CURVE.n), Point: P384.ProjectivePoint, h2c: hashToP384 },
    [Group.ID.P521]: { fp: Fp(P521.CURVE.n), Point: P521.ProjectivePoint, h2c: hashToP521 }
}
function getCurve(gid: GroupID) {
    /* eslint-disable */
    if (![Group.ID.P256, Group.ID.P384, Group.ID.P521].includes(gid)) throw errBadGroup(gid)
    return curves[gid]
}
