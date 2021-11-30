// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { hashParams, joinAll, xor } from './util.js'

import sjcl from './sjcl/index.js'

export class SerializedElt extends Uint8Array {
    readonly _serializedEltBrand = ''
}

export class SerializedScalar extends Uint8Array {
    readonly _serializedScalarBrand = ''
}

// Elt is a sjcl.ecc.point
type Elt = any
// Scalar is a sjcl.bn
type Scalar = any
// Curve is a sjcl.ecc.curve
type Curve = any
// Scalar is a sjcl.bn
type FieldElt = any

async function expandXMD(
    hash: string,
    msg: Uint8Array,
    dst: Uint8Array,
    numBytes: number
): Promise<Uint8Array> {
    const { outLenBytes, blockLenBytes } = hashParams(hash),
        ell = Math.ceil(numBytes / outLenBytes)

    if (ell > 255) {
        throw new Error('too big')
    }

    let dstPrime = dst
    if (dst.length > 255) {
        const te = new TextEncoder(),
            input = joinAll([te.encode('H2C-OVERSIZE-DST-'), dst])
        dstPrime = new Uint8Array(await crypto.subtle.digest(hash, input))
    }
    dstPrime = joinAll([dstPrime, new Uint8Array([dstPrime.length])])

    const zPad = new Uint8Array(blockLenBytes),
        libStr = new Uint8Array(2)
    libStr[0] = (numBytes >> 8) & 0xff
    libStr[1] = numBytes & 0xff
    const b0Input = joinAll([zPad, msg, libStr, new Uint8Array([0]), dstPrime]),
        b0 = new Uint8Array(await crypto.subtle.digest(hash, b0Input)),
        b1Input = joinAll([b0, new Uint8Array([1]), dstPrime])
    let bi = new Uint8Array(await crypto.subtle.digest(hash, b1Input)),
        pseudo = joinAll([bi])

    for (let i = 2; i <= ell; i++) {
        const biInput = joinAll([xor(bi, b0), new Uint8Array([i]), dstPrime])
        bi = new Uint8Array(await crypto.subtle.digest(hash, biInput)) // eslint-disable-line no-await-in-loop
        pseudo = joinAll([pseudo, bi])
    }
    return pseudo.slice(0, numBytes)
}

export enum GroupID { // eslint-disable-line no-shadow
    P256 = 'P-256',
    P384 = 'P-384',
    P521 = 'P-521'
}

/* eslint new-cap: ["error", { "properties": false }] */

export class Group {
    static readonly paranoia = 6

    public readonly id: GroupID

    public readonly curve: Curve

    public readonly size: number

    public hashParams: {
        hash: string
        L: number
        Z: number
        c2: string
    }

    constructor(gid: GroupID) {
        switch (gid) {
            case GroupID.P256:
                this.curve = sjcl.ecc.curves.c256
                this.size = 32
                this.hashParams = {
                    hash: 'SHA-256',
                    L: 48,
                    Z: -10,
                    c2: '0x78bc71a02d89ec07214623f6d0f955072c7cc05604a5a6e23ffbf67115fa5301'
                }
                break
            case GroupID.P384:
                this.curve = sjcl.ecc.curves.c384
                this.size = 48
                this.hashParams = {
                    hash: 'SHA-384',
                    L: 72,
                    Z: -12,
                    c2: '0x19877cc1041b7555743c0ae2e3a3e61fb2aaa2e0e87ea557a563d8b598a0940d0a697a9e0b9e92cfaa314f583c9d066'
                }
                break
            case GroupID.P521:
                this.curve = sjcl.ecc.curves.c521
                this.size = 66
                this.hashParams = {
                    hash: 'SHA-512',
                    L: 98,
                    Z: -4,
                    c2: '0x8'
                }
                break
            default:
                throw new Error(`group not implemented: ${gid}`)
        }
        this.id = gid
    }

    static getID(id: string): GroupID {
        switch (id) {
            case 'P-256':
                return GroupID.P256
            case 'P-384':
                return GroupID.P384
            case 'P-521':
                return GroupID.P521
            default:
                throw new Error(`group not implemented: ${id}`)
        }
    }

    identity(): Elt {
        return new sjcl.ecc.point(this.curve) as Elt
    }

    generator(): Elt {
        return this.curve.G as Elt
    }

    order(): Scalar {
        return this.curve.r as Scalar
    }

    // Serializes an element in uncompressed form.
    private serUnComp(e: Elt): SerializedElt {
        const xy = sjcl.codec.arrayBuffer.fromBits(e.toBits(), false),
            bytes = new Uint8Array(xy)
        if (bytes.length !== 2 * this.size) {
            throw new Error('error serializing element')
        }
        const serElt = new SerializedElt(1 + 2 * this.size)
        serElt[0] = 0x04
        serElt.set(bytes, 1)
        return serElt
    }

    // Serializes an element in compressed form.
    private serComp(e: Elt): SerializedElt {
        const x = sjcl.codec.arrayBuffer.fromBits(e.x.toBits(), false),
            bytes = new Uint8Array(x),
            serElt = new SerializedElt(1 + this.size)

        serElt[0] = 0x02 | (e.y.limbs[0] & 1)
        serElt.set(bytes, 1 + this.size - bytes.length)
        return serElt
    }

    serialize(e: Elt, compressed = true): SerializedElt {
        if (e.isIdentity) {
            return new SerializedElt(1)
        }
        e.x.fullReduce()
        e.y.fullReduce()
        return compressed ? this.serComp(e) : this.serUnComp(e)
    }

    // Deserializes an element in compressed form.
    private deserComp(serElt: SerializedElt): Elt {
        const array = Array.from(serElt.slice(1)),
            bytes = sjcl.codec.bytes.toBits(array),
            x = new this.curve.field(sjcl.bn.fromBits(bytes)),
            p = this.curve.field.modulus,
            exp = p.add(new sjcl.bn(1)).halveM().halveM()
        let y = x.square().add(this.curve.a).mul(x).add(this.curve.b).power(exp)
        y.fullReduce()
        if ((serElt[0] & 1) !== (y.limbs[0] & 1)) {
            y = p.sub(y).mod(p)
        }
        const point = new sjcl.ecc.point(this.curve, new sjcl.bn(x), new sjcl.bn(y))
        if (!point.isValid()) {
            throw new Error('point not in curve')
        }
        return point as Elt
    }

    // Deserializes an element in uncompressed form.
    private deserUnComp(serElt: SerializedElt): Elt {
        const array = Array.from(serElt.slice(1)),
            b = sjcl.codec.bytes.toBits(array),
            point = this.curve.fromBits(b)
        point.x.fullReduce()
        point.y.fullReduce()
        return point as Elt
    }

    // Deserializes an element, handles both compressed and uncompressed forms.
    deserialize(serElt: SerializedElt): Elt {
        const len = serElt.length
        switch (true) {
            case len === 1 && serElt[0] === 0x00:
                return this.identity()
            case len === 1 + this.size && (serElt[0] === 0x02 || serElt[0] === 0x03):
                return this.deserComp(serElt)
            case len === 1 + 2 * this.size && serElt[0] === 0x04:
                return this.deserUnComp(serElt)
            default:
                throw new Error('error deserializing element')
        }
    }

    serializeScalar(s: Scalar): SerializedScalar {
        const k = s.mod(this.curve.r)
        k.normalize()

        const ab = sjcl.codec.arrayBuffer.fromBits(k.toBits(), false),
            unpaded = new Uint8Array(ab),
            serScalar = new SerializedScalar(this.size)
        serScalar.set(unpaded, this.size - unpaded.length)
        return serScalar
    }

    deserializeScalar(serScalar: SerializedScalar): Scalar {
        const array = Array.from(serScalar),
            k = sjcl.bn.fromBits(sjcl.codec.bytes.toBits(array))
        k.normalize()
        if (k.greaterEquals(this.curve.r)) {
            throw new Error('error deserializing scalar')
        }
        return k as Scalar
    }

    addScalar(a: Scalar, b: Scalar): Scalar {
        const c = a.add(b)
        c.mod(this.curve.r)
        c.normalize()
        return c
    }

    invScalar(k: Scalar): Scalar {
        return k.inverseMod(this.curve.r)
    }

    static mul(k: Scalar, e: Elt): Elt {
        return e.mult(k) as Elt
    }

    mulBase(k: Scalar): Elt {
        return this.curve.G.mult(k) as Elt
    }

    equal(a: Elt, b: Elt): boolean {
        if (this.curve !== a.curve || this.curve !== b.curve) {
            return false
        }
        if (a.isIdentity && b.isIdentity) {
            return true
        }
        return a.x.equals(b.x) && a.y.equals(b.y)
    }

    randomScalar(): Promise<Scalar> {
        const msg = new Uint8Array(this.hashParams.L)
        crypto.getRandomValues(msg)
        return this.hashToScalar(msg, new Uint8Array())
    }

    async hashToScalar(msg: Uint8Array, dst: Uint8Array): Promise<Scalar> {
        const { hash, L } = this.hashParams,
            bytes = await expandXMD(hash, msg, dst, L),
            array = Array.from(bytes),
            bitArr = sjcl.codec.bytes.toBits(array),
            s = sjcl.bn.fromBits(bitArr).mod(this.curve.r)
        return s as Scalar
    }

    async hashToGroup(msg: Uint8Array, dst: Uint8Array): Promise<Elt> {
        const u = await this.hashToField(msg, dst, 2),
            Q0 = this.sswu(u[0]),
            Q1 = this.sswu(u[1])
        return Q0.toJac().add(Q1).toAffine() as Elt
    }

    private async hashToField(
        msg: Uint8Array,
        dst: Uint8Array,
        count: number
    ): Promise<FieldElt[]> {
        const { hash, L } = this.hashParams,
            bytes = await expandXMD(hash, msg, dst, count * L),
            u = new Array<FieldElt>(count)
        for (let i = 0; i < count; i++) {
            const j = i * L,
                array = Array.from(bytes.slice(j, j + L)),
                bitArr = sjcl.codec.bytes.toBits(array)
            u[i as number] = new this.curve.field(sjcl.bn.fromBits(bitArr))
        }
        return u
    }

    private sswu(u: FieldElt): Elt {
        const A = this.curve.a,
            B = this.curve.b,
            p = this.curve.field.modulus,
            Z = new this.curve.field(this.hashParams.Z),
            c2 = new sjcl.bn(this.hashParams.c2),
            c1 = p.sub(new sjcl.bn(3)).halveM().halveM(), // c1 = (p-3)/4
            zero = new this.curve.field(0),
            one = new this.curve.field(1)

        function sgn(x: FieldElt): number {
            x.fullReduce()
            return x.limbs[0] & 1
        }
        function cmov(x: FieldElt, y: FieldElt, b: boolean): FieldElt {
            return b ? y : x
        }

        let tv1 = u.square() //          1. tv1 = u^2
        const tv3 = Z.mul(tv1) //        2. tv3 = Z * tv1
        let tv2 = tv3.square(), //       3. tv2 = tv3^2
            xd = tv2.add(tv3), //        4.  xd = tv2 + tv3
            x1n = xd.add(one) //         5. x1n = xd + 1
        x1n = x1n.mul(B) //              6. x1n = x1n * B
        let tv4 = p.sub(A)
        xd = xd.mul(tv4) //              7.  xd = -A * xd
        const e1 = xd.equals(zero) //    8.  e1 = xd == 0
        tv4 = A.mul(Z)
        xd = cmov(xd, tv4, e1) //        9.  xd = CMOV(xd, Z * A, e1)
        tv2 = xd.square() //            10. tv2 = xd^2
        const gxd = tv2.mul(xd) //      11. gxd = tv2 * xd
        tv2 = tv2.mul(A) //             12. tv2 = A * tv2
        let gx1 = x1n.square() //       13. gx1 = x1n^2
        gx1 = gx1.add(tv2) //           14. gx1 = gx1 + tv2
        gx1 = gx1.mul(x1n) //           15. gx1 = gx1 * x1n
        tv2 = gxd.mul(B) //             16. tv2 = B * gxd
        gx1 = gx1.add(tv2) //           17. gx1 = gx1 + tv2
        tv4 = gxd.square() //           18. tv4 = gxd^2
        tv2 = gx1.mul(gxd) //           19. tv2 = gx1 * gxd
        tv4 = tv4.mul(tv2) //           20. tv4 = tv4 * tv2
        let y1 = tv4.power(c1) //       21.  y1 = tv4^c1
        y1 = y1.mul(tv2) //             22.  y1 = y1 * tv2
        const x2n = tv3.mul(x1n) //     23. x2n = tv3 * x1n
        let y2 = y1.mul(c2) //          24.  y2 = y1 * c2
        y2 = y2.mul(tv1) //             25.  y2 = y2 * tv1
        y2 = y2.mul(u) //               26.  y2 = y2 * u
        tv2 = y1.square() //            27. tv2 = y1^2
        tv2 = tv2.mul(gxd) //           28. tv2 = tv2 * gxd
        const e2 = tv2.equals(gx1), //  29.  e2 = tv2 == gx1
            xn = cmov(x2n, x1n, e2) //  30.  xn = CMOV(x2n, x1n, e2)
        let y = cmov(y2, y1, e2) //     31.   y = CMOV(y2, y1, e2)
        const e3 = sgn(u) === sgn(y) // 32.  e3 = sgn0(u) == sgn0(y)
        tv1 = p.sub(y)
        y = cmov(tv1, y, e3) //         33.   y = CMOV(-y, y, e3)
        let x = xd.inverseMod(p) //     34. return (xn, xd, y, 1)
        x = xn.mul(x)

        const point = new sjcl.ecc.point(this.curve, new sjcl.bn(x), new sjcl.bn(y))
        if (!point.isValid()) {
            throw new Error('point not in curve')
        }
        return point as Elt
    }
}
