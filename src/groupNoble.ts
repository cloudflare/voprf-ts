// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { checkSize } from './util.js'
import * as p256 from '@noble/curves/p256'
import * as p384 from '@noble/curves/p384'
import * as p521 from '@noble/curves/p521'
import { Field } from '@noble/curves/abstract/modular'
import { bytesToNumberBE } from '@noble/curves/abstract/utils'
import { hash_to_field } from '@noble/curves/abstract/hash-to-curve'
import { CurveFn, ProjConstructor, ProjPointType } from '@noble/curves/abstract/weierstrass'
import { CHash } from '@noble/hashes/utils'
import {
    Deserializer,
    Elt,
    EltCons,
    Group,
    GroupCons,
    GroupID,
    GroupIDs,
    Scalar,
    ScalarCons
} from './groupTypes.js'

type FieldFn = ReturnType<typeof Field>
type H2CFn = typeof p256.hashToCurve
type NobleModule<K extends string> = Record<K, CurveFn> & { hashToCurve: H2CFn }

interface GroupParams {
    scalarField: FieldFn
    Point: ProjConstructor<bigint>
    h2c: H2CFn
    size: number
    hashToScalar: {
        hash: CHash
        k: number
        p: bigint
    }
}

function makeParams<K extends string>(
    k: K,
    module: NobleModule<K>,
    securityBits: number
): GroupParams {
    const curve = Reflect.get(module, k)
    return {
        scalarField: Field(curve.CURVE.n),
        Point: curve.ProjectivePoint,
        h2c: module.hashToCurve,
        size: curve.CURVE.Fp.BYTES,
        hashToScalar: {
            hash: curve.CURVE.hash,
            p: curve.CURVE.n,
            k: securityBits
        }
    }
}

const GROUPS: Record<GroupID, GroupParams> = {
    [GroupIDs.P256]: makeParams('p256', p256, 128),
    [GroupIDs.P384]: makeParams('p384', p384, 192),
    [GroupIDs.P521]: makeParams('p521', p521, 256)
}

function getParams(gid: GroupID) {
    if (!Object.values(GroupIDs).includes(gid)) throw errBadGroup(gid)
    // eslint-disable-next-line security/detect-object-injection
    return GROUPS[gid]
}

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

// TODO: h2c/h2f only accepts a string, otherwise throws an error, open an issue
function decodeDST(val: Uint8Array): string {
    return new TextDecoder().decode(val)
}

class ScalarNb implements Scalar {
    private readonly field: FieldFn
    public readonly k: bigint

    private constructor(public readonly g: GroupNb, k: bigint) {
        this.field = this.g.params.scalarField
        this.k = this.field.create(k)
    }

    static new(g: GroupNb): ScalarNb {
        return new ScalarNb(g, BigInt(0))
    }

    isEqual(s: ScalarNb): boolean {
        return this.k === s.k
    }

    isZero(): boolean {
        return this.k === BigInt(0)
    }

    add(s: ScalarNb): ScalarNb {
        compat(this, s)
        return new ScalarNb(this.g, this.field.add(this.k, s.k))
    }

    sub(s: ScalarNb): ScalarNb {
        compat(this, s)
        return new ScalarNb(this.g, this.field.sub(this.k, s.k))
    }

    mul(s: ScalarNb): ScalarNb {
        compat(this, s)
        return new ScalarNb(this.g, this.field.mul(this.k, s.k))
    }

    inv(): ScalarNb {
        return new ScalarNb(this.g, this.field.inv(this.k))
    }

    serialize(): Uint8Array {
        const k = this.field.create(this.k)
        const ab = this.field.toBytes(k)
        const unPadded = new Uint8Array(ab)
        const serScalar = new Uint8Array(this.g.size)
        serScalar.set(unPadded, this.g.size - unPadded.length)
        return serScalar
    }

    static size(g: GroupNb): number {
        return g.size
    }

    static deserialize(g: GroupNb, bytes: Uint8Array): ScalarNb {
        checkSize(bytes, ScalarNb, g)
        const array = bytes.subarray(0, g.size)
        const k = bytesToNumberBE(array)
        if (k >= g.params.scalarField.ORDER) {
            throw errDeserialization(ScalarNb)
        }
        return new ScalarNb(g, k)
    }

    static hash(g: GroupNb, msg: Uint8Array, dst: Uint8Array): ScalarNb {
        const [[k]] = hash_to_field(msg, 1, {
            ...g.params.hashToScalar,
            expand: 'xmd',
            DST: decodeDST(dst),
            m: 1
        })
        return new ScalarNb(g, k)
    }
}

class EltNb implements Elt {
    private constructor(public readonly g: GroupNb, private readonly p: ProjPointType<bigint>) {}

    static new(g: GroupNb): EltNb {
        return new EltNb(g, g.params.Point.ZERO)
    }

    static gen(g: GroupNb): EltNb {
        return new EltNb(g, g.params.Point.BASE)
    }

    isIdentity(): boolean {
        return this.p.equals(this.g.params.Point.ZERO)
    }

    isEqual(a: EltNb): boolean {
        compat(this, a)
        return this.p.equals(a.p)
    }

    neg(): EltNb {
        return new EltNb(this.g, this.p.negate())
    }

    add(a: EltNb): EltNb {
        compat(this, a)
        return new EltNb(this.g, this.p.add(a.p))
    }

    mul(s: ScalarNb): EltNb {
        compat(this, s)
        return new EltNb(this.g, this.p.multiply(s.k))
    }

    mul2(k1: ScalarNb, a: EltNb, k2: ScalarNb): EltNb {
        compat(this, k1)
        compat(this, k2)
        compat(this, a)
        const zero = this.g.params.Point.ZERO
        const el = this.p.multiplyAndAddUnsafe(a.p, k1.k, k2.k) ?? zero
        return new EltNb(this.g, el)
    }

    serialize(compressed = true): Uint8Array {
        if (this.isIdentity()) {
            return Uint8Array.from([0])
        }
        return this.p.toRawBytes(compressed)
    }

    // size returns the number of bytes of a non-zero element in compressed or uncompressed form.
    static size(g: GroupNb, compressed = true): number {
        return 1 + (compressed ? g.size : g.size * 2)
    }

    private static deser(g: GroupNb, bytes: Uint8Array): EltNb {
        const point = g.params.Point.fromHex(bytes)
        point.assertValidity()
        return new EltNb(g, point)
    }

    // Deserializes an element, handles both compressed and uncompressed forms.
    static deserialize(g: GroupNb, bytes: Uint8Array): EltNb {
        const len = bytes.length
        switch (true) {
            case len === 1 && bytes[0] === 0x00:
                return g.identity()
            case len === 1 + g.size && (bytes[0] === 0x02 || bytes[0] === 0x03):
                return EltNb.deser(g, bytes)
            case len === 1 + 2 * g.size && bytes[0] === 0x04:
                return EltNb.deser(g, bytes)
            default:
                throw errDeserialization(EltNb)
        }
    }

    static hash(g: GroupNb, msg: Uint8Array, dst: Uint8Array): EltNb {
        const h2c = g.params.h2c
        const p = h2c(msg, { DST: decodeDST(dst) }) as ProjPointType<bigint>
        return new EltNb(g, p)
    }
}

class GroupNb implements Group {
    static readonly Elt: EltCons = EltNb
    static readonly Scalar: ScalarCons = ScalarNb
    static readonly ID = GroupIDs

    static fromID(gid: GroupID) {
        return new this(gid)
    }

    public readonly params: GroupParams
    public readonly size: number
    public readonly id: GroupID

    constructor(gid: GroupID) {
        this.params = getParams(gid)
        this.size = this.params.size
        this.id = gid
    }

    newScalar(): ScalarNb {
        return ScalarNb.new(this)
    }

    newElt(): EltNb {
        return this.identity()
    }

    identity(): EltNb {
        return EltNb.new(this)
    }

    generator(): EltNb {
        return EltNb.gen(this)
    }

    mulGen(s: ScalarNb): EltNb {
        return EltNb.gen(this).mul(s)
    }

    randomScalar(): Promise<ScalarNb> {
        const msg = crypto.getRandomValues(new Uint8Array(this.size))
        return Promise.resolve(ScalarNb.hash(this, msg, new Uint8Array()))
    }

    async hashToGroup(msg: Uint8Array, dst: Uint8Array): Promise<EltNb> {
        return EltNb.hash(this, msg, dst)
    }

    async hashToScalar(msg: Uint8Array, dst: Uint8Array): Promise<ScalarNb> {
        return ScalarNb.hash(this, msg, dst)
    }

    readonly eltDes: Deserializer<EltNb> = {
        size: (compressed) => this.eltSize(compressed),
        deserialize: (b) => this.desElt(b)
    }

    readonly scalarDes: Deserializer<ScalarNb> = {
        size: () => this.scalarSize(),
        deserialize: (b) => this.desScalar(b)
    }

    desElt(bytes: Uint8Array): EltNb {
        return EltNb.deserialize(this, bytes)
    }

    desScalar(bytes: Uint8Array): ScalarNb {
        return ScalarNb.deserialize(this, bytes)
    }

    eltSize(compressed?: boolean): number {
        return EltNb.size(this, compressed)
    }

    scalarSize(): number {
        return ScalarNb.size(this)
    }
}

export const GroupConsNoble: GroupCons = GroupNb
