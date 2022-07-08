// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { checkSize, joinAll, xor } from './util.js'

import sjcl from './sjcl/index.js'

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

function hashParams(hash: string): {
    outLenBytes: number // returns the size in bytes of the output.
    blockLenBytes: number // returns the size of the internal block.
} {
    switch (hash) {
        case 'SHA-1':
            return { outLenBytes: 20, blockLenBytes: 64 }
        case 'SHA-256':
            return { outLenBytes: 32, blockLenBytes: 64 }
        case 'SHA-384':
            return { outLenBytes: 48, blockLenBytes: 128 }
        case 'SHA-512':
            return { outLenBytes: 64, blockLenBytes: 128 }
        default:
            throw new Error(`invalid hash name: ${hash}`)
    }
}

async function expandXMD(
    hash: string,
    msg: Uint8Array,
    dst: Uint8Array,
    numBytes: number
): Promise<Uint8Array> {
    const { outLenBytes, blockLenBytes } = hashParams(hash)
    const ell = Math.ceil(numBytes / outLenBytes)

    if (ell > 255) {
        throw new Error('too big')
    }

    let dstPrime = dst
    if (dst.length > 255) {
        const te = new TextEncoder()
        const input = joinAll([te.encode('H2C-OVERSIZE-DST-'), dst])
        dstPrime = new Uint8Array(await crypto.subtle.digest(hash, input))
    }
    dstPrime = joinAll([dstPrime, new Uint8Array([dstPrime.length])])

    const zPad = new Uint8Array(blockLenBytes)
    const libStr = new Uint8Array(2)
    libStr[0] = (numBytes >> 8) & 0xff
    libStr[1] = numBytes & 0xff
    const b0Input = joinAll([zPad, msg, libStr, new Uint8Array([0]), dstPrime])
    const b0 = new Uint8Array(await crypto.subtle.digest(hash, b0Input))
    const b1Input = joinAll([b0, new Uint8Array([1]), dstPrime])
    let bi = new Uint8Array(await crypto.subtle.digest(hash, b1Input))
    let pseudo = joinAll([bi])

    for (let i = 2; i <= ell; i++) {
        const biInput = joinAll([xor(bi, b0), new Uint8Array([i]), dstPrime])
        bi = new Uint8Array(await crypto.subtle.digest(hash, biInput)) // eslint-disable-line no-await-in-loop
        pseudo = joinAll([pseudo, bi])
    }
    return pseudo.slice(0, numBytes)
}

function getCurve(gid: GroupID): sjcl.ecc.curve {
    switch (gid) {
        case Group.ID.P256:
            return sjcl.ecc.curves.c256
        case Group.ID.P384:
            return sjcl.ecc.curves.c384
        case Group.ID.P521:
            return sjcl.ecc.curves.c521
        default:
            throw errBadGroup(gid)
    }
}

export class Scalar {
    private readonly order: sjcl.bn

    private constructor(public readonly g: Group, private readonly k: sjcl.bn) {
        this.order = getCurve(this.g.id).r
    }

    static new(g: Group): Scalar {
        return new Scalar(g, new sjcl.bn(0))
    }

    isEqual(s: Scalar): boolean {
        return this.k.equals(s.k)
    }

    isZero(): boolean {
        return this.k.equals(0)
    }

    add(s: Scalar): Scalar {
        compat(this, s)
        const c = this.k.add(s.k).mod(this.order)
        c.normalize()
        return new Scalar(this.g, c)
    }

    sub(s: Scalar): Scalar {
        compat(this, s)
        const c = this.k.sub(s.k).mod(this.order)
        c.normalize()
        return new Scalar(this.g, c)
    }

    mul(s: Scalar): Scalar {
        compat(this, s)
        const c = this.k.mulmod(s.k, this.order)
        c.normalize()
        return new Scalar(this.g, c)
    }

    inv(): Scalar {
        return new Scalar(this.g, this.k.inverseMod(this.order))
    }

    serialize(): Uint8Array {
        const k = this.k.mod(this.order)
        k.normalize()

        const ab = sjcl.codec.arrayBuffer.fromBits(k.toBits(), false)
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
        const array = Array.from(bytes.subarray(0, g.size))
        const k = sjcl.bn.fromBits(sjcl.codec.bytes.toBits(array))
        k.normalize()
        if (k.greaterEquals(getCurve(g.id).r)) {
            throw errDeserialization(Scalar)
        }
        return new Scalar(g, k)
    }

    static async hash(g: Group, msg: Uint8Array, dst: Uint8Array): Promise<Scalar> {
        const { hash, L } = getHashParams(g.id)
        const bytes = await expandXMD(hash, msg, dst, L)
        const array = Array.from(bytes)
        const bitArr = sjcl.codec.bytes.toBits(array)
        const k = sjcl.bn.fromBits(bitArr).mod(getCurve(g.id).r)
        return new Scalar(g, k)
    }
}

interface InnerScalar {
    readonly k: unknown
}

interface SSWUParams {
    // See Section F.2.1.2 at https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-14#appendix-F.2.1.2
    Z: sjcl.bn
    c1: sjcl.bn // 1. c1 = (p-3)/4
    c2: sjcl.bn // 2. c2 = sqrt(-Z) in GF(p).
}

function getSSWUParams(gid: GroupID): SSWUParams {
    const curve = getCurve(gid)
    let Z
    let c2
    switch (gid) {
        case Group.ID.P256:
            Z = -10
            // c2 = sqrt(-Z) in GF(p).
            c2 = '0x25ac71c31e27646736870398ae7f554d8472e008b3aa2a49d332cbd81bcc3b80'

            break
        case Group.ID.P384:
            Z = -12
            // c2 = sqrt(-Z) in GF(p).
            c2 =
                '0x2accb4a656b0249c71f0500e83da2fdd7f98e383d68b53871f872fcb9ccb80c53c0de1f8a80f7e1914e2ec69f5a626b3'
            break
        case Group.ID.P521:
            Z = -4
            // c2 = sqrt(-Z) in GF(p).
            c2 = '0x2'
            break
        default:
            throw errBadGroup(gid)
    }

    const p = curve.field.modulus
    const c1 = p.sub(new sjcl.bn(3)).halveM().halveM()
    Z = new curve.field(Z)
    c2 = new curve.field(c2)

    return { Z, c1, c2 }
}

interface HashParams {
    hash: string
    L: number
}

function getHashParams(gid: GroupID): HashParams {
    switch (gid) {
        case Group.ID.P256:
            return { hash: 'SHA-256', L: 48 }
        case Group.ID.P384:
            return { hash: 'SHA-384', L: 72 }
        case Group.ID.P521:
            return { hash: 'SHA-512', L: 98 }
        default:
            throw errBadGroup(gid)
    }
}

export class Elt {
    private constructor(public readonly g: Group, private readonly p: sjcl.ecc.point) {}

    static new(g: Group): Elt {
        return new Elt(g, new sjcl.ecc.point(getCurve(g.id)))
    }
    static gen(g: Group): Elt {
        return new Elt(g, getCurve(g.id).G)
    }

    isIdentity(): boolean {
        return this.p.isIdentity
    }

    isEqual(a: Elt): boolean {
        compat(this, a)
        if (this.p.isIdentity && a.p.isIdentity) {
            return true
        } else if (this.p.isIdentity || a.p.isIdentity) {
            return false
        }
        const { x: x1, y: y1 } = this.p
        const { x: x2, y: y2 } = a.p
        return x1.equals(x2) && y1.equals(y2)
    }

    neg(): Elt {
        return this.p.negate()
    }
    add(a: Elt): Elt {
        compat(this, a)
        return new Elt(this.g, this.p.toJac().add(a.p).toAffine())
    }
    mul(s: Scalar): Elt {
        compat(this, s)
        return new Elt(this.g, this.p.mult((s as unknown as InnerScalar).k))
    }
    mul2(k1: Scalar, a: Elt, k2: Scalar): Elt {
        compat(this, k1)
        compat(this, k2)
        compat(this, a)
        return new Elt(
            this.g,
            this.p.mult2((k1 as unknown as InnerScalar).k, (k2 as unknown as InnerScalar).k, a.p)
        )
    }
    // Serializes an element in uncompressed form.
    private serUnComp(a: sjcl.ecc.point): Uint8Array {
        const xy = sjcl.codec.arrayBuffer.fromBits(a.toBits(), false)
        const bytes = new Uint8Array(xy)
        if (bytes.length !== 2 * this.g.size) {
            throw new Error('error serializing element')
        }
        const serElt = new Uint8Array(1 + 2 * this.g.size)
        serElt[0] = 0x04
        serElt.set(bytes, 1)
        return serElt
    }

    // Serializes an element in compressed form.
    private serComp(a: sjcl.ecc.point): Uint8Array {
        const x = new Uint8Array(sjcl.codec.arrayBuffer.fromBits(a.x.toBits(null), false))
        const serElt = new Uint8Array(1 + this.g.size)

        serElt[0] = 0x02 | (a.y.getLimb(0) & 1)
        serElt.set(x, 1 + this.g.size - x.length)
        return serElt
    }

    serialize(compressed = true): Uint8Array {
        if (this.p.isIdentity) {
            return Uint8Array.from([0])
        }
        const p = this.p
        p.x.fullReduce()
        p.y.fullReduce()
        return compressed ? this.serComp(p) : this.serUnComp(p)
    }

    // size returns the number of bytes of a non-zero element in compressed or uncompressed form.
    static size(g: Group, compressed = true): number {
        return 1 + (compressed ? g.size : g.size * 2)
    }

    // Deserializes an element in compressed form.
    private static deserComp(g: Group, bytes: Uint8Array): Elt {
        const array = Array.from(bytes.subarray(1))
        const bits = sjcl.codec.bytes.toBits(array)
        const curve = getCurve(g.id)
        const x = new curve.field(sjcl.bn.fromBits(bits))
        const p = curve.field.modulus
        const exp = p.add(new sjcl.bn(1)).halveM().halveM()
        let y = x.square().add(curve.a).mul(x).add(curve.b).power(exp)
        y.fullReduce()
        if ((bytes[0] & 1) !== (y.getLimb(0) & 1)) {
            y = p.sub(y).mod(p)
        }
        const point = new sjcl.ecc.point(curve, new curve.field(x), new curve.field(y))
        if (!point.isValid()) {
            throw errDeserialization(Elt)
        }
        return new Elt(g, point)
    }

    // Deserializes an element in uncompressed form.
    private static deserUnComp(g: Group, bytes: Uint8Array): Elt {
        const array = Array.from(bytes.subarray(1))
        const b = sjcl.codec.bytes.toBits(array)
        const curve = getCurve(g.id)
        const point = curve.fromBits(b)
        point.x.fullReduce()
        point.y.fullReduce()
        return new Elt(g, point)
    }

    // Deserializes an element, handles both compressed and uncompressed forms.
    static deserialize(g: Group, bytes: Uint8Array): Elt {
        const len = bytes.length
        switch (true) {
            case len === 1 && bytes[0] === 0x00:
                return g.identity()
            case len === 1 + g.size && (bytes[0] === 0x02 || bytes[0] === 0x03):
                return Elt.deserComp(g, bytes)
            case len === 1 + 2 * g.size && bytes[0] === 0x04:
                return Elt.deserUnComp(g, bytes)
            default:
                throw errDeserialization(Elt)
        }
    }

    private static async hashToField(
        g: Group,
        msg: Uint8Array,
        dst: Uint8Array,
        count: number
    ): Promise<sjcl.bn[]> {
        const curve = getCurve(g.id)
        const { hash, L } = getHashParams(g.id)
        const bytes = await expandXMD(hash, msg, dst, count * L)
        const u = new Array<sjcl.bn>()
        for (let i = 0; i < count; i++) {
            const j = i * L
            const array = Array.from(bytes.slice(j, j + L))
            const bitArr = sjcl.codec.bytes.toBits(array)
            u.push(new curve.field(sjcl.bn.fromBits(bitArr)))
        }
        return u
    }

    private static sswu(g: Group, u: sjcl.bn): Elt {
        // Simplified SWU method.
        // Appendix F.2 of draft-irtf-cfrg-hash-to-curve-14
        // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-14#appendix-F.2
        const curve = getCurve(g.id)
        const { a: A, b: B } = curve
        const { Z, c1, c2 } = getSSWUParams(g.id)
        const zero = new curve.field(0)
        const one = new curve.field(1)

        function sgn(x: sjcl.bn): number {
            x.fullReduce()
            return x.getLimb(0) & 1
        }
        function cmov(x: sjcl.bn, y: sjcl.bn, b: boolean): sjcl.bn {
            return b ? y : x
        }
        // Input: u and v, elements of F, where v != 0.
        // Output: (isQR, root), where
        //   isQR = True  and root = sqrt(u / v) if (u / v) is square in F, and
        //   isQR = False and root = sqrt(Z * (u / v)) otherwise.
        function sqrt_ratio_3mod4(u: sjcl.bn, v: sjcl.bn): { isQR: boolean; root: sjcl.bn } {
            let tv1 = v.square() //         1. tv1 = v^2
            const tv2 = u.mul(v) //         2. tv2 = u * v
            tv1 = tv1.mul(tv2) //           3. tv1 = tv1 * tv2
            let y1 = tv1.power(c1) //       4. y1 = tv1^c1
            y1 = y1.mul(tv2) //             5. y1 = y1 * tv2
            const y2 = y1.mul(c2) //        6. y2 = y1 * c2
            let tv3 = y1.square() //        7. tv3 = y1^2
            tv3 = tv3.mul(v) //             8. tv3 = tv3 * v
            const isQR = tv3.equals(u) //   9. isQR = tv3 == u
            const y = cmov(y2, y1, isQR) // 10. y = CMOV(y2, y1, isQR)
            return { isQR, root: y } //     11. return (isQR, y)
        }

        let tv1 = u.square() //         1.  tv1 = u^2
        tv1 = Z.mul(tv1) //             2.  tv1 = Z * tv1
        let tv2 = tv1.square() //       3.  tv2 = tv1^2
        tv2 = tv2.add(tv1) //           4.  tv2 = tv2 + tv1
        let tv3 = tv2.add(one) //       5.  tv3 = tv2 + 1
        tv3 = B.mul(tv3) //             6.  tv3 = B * tv3
        let tv4 = cmov(Z, zero.sub(tv2), !tv2.equals(zero)) // 7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
        tv4 = A.mul(tv4) //             8.  tv4 = A * tv4
        tv2 = tv3.square() //           9.  tv2 = tv3^2
        let tv6 = tv4.square() //       10. tv6 = tv4^2
        let tv5 = A.mul(tv6) //         11. tv5 = A * tv6
        tv2 = tv2.add(tv5) //           12. tv2 = tv2 + tv5
        tv2 = tv2.mul(tv3) //           13. tv2 = tv2 * tv3
        tv6 = tv6.mul(tv4) //           14. tv6 = tv6 * tv4
        tv5 = B.mul(tv6) //             15. tv5 = B * tv6
        tv2 = tv2.add(tv5) //           16. tv2 = tv2 + tv5
        let x = tv1.mul(tv3) //         17.   x = tv1 * tv3
        const { isQR, root: y1 } = sqrt_ratio_3mod4(tv2, tv6) // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
        let y = tv1.mul(u) //           19.   y = tv1 * u
        y = y.mul(y1) //                20.   y = y * y1
        x = cmov(x, tv3, isQR) //       21.   x = CMOV(x, tv3, is_gx1_square)
        y = cmov(y, y1, isQR) //        22.   y = CMOV(y, y1, is_gx1_square)
        const e1 = sgn(u) === sgn(y) // 23.  e1 = sgn0(u) == sgn0(y)
        y = cmov(zero.sub(y), y, e1) // 24.   y = CMOV(-y, y, e1)
        const z = tv4 //                25.   x = x / tv4
        x = x.mul(z) //                 26. return (x, y, z)
        tv1 = z.square()
        tv1 = tv1.mul(z)
        y = y.mul(tv1)

        const point = new sjcl.ecc.pointJac(curve, x, y, z).toAffine()
        if (!point.isValid()) {
            throw new Error('point not in curve')
        }
        return new Elt(g, point)
    }

    static async hash(g: Group, msg: Uint8Array, dst: Uint8Array): Promise<Elt> {
        const u = await Elt.hashToField(g, msg, dst, 2)
        const Q0 = Elt.sswu(g, u[0])
        const Q1 = Elt.sswu(g, u[1])
        return Q0.add(Q1)
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
