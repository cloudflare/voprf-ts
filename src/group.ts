// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { joinAll, xor } from './util.js'

import sjcl from './sjcl/index.js'

export class SerializedElt extends Uint8Array {
    readonly _serializedEltBrand = ''
}

export class SerializedScalar extends Uint8Array {
    readonly _serializedScalarBrand = ''
}

export type Elt = sjcl.ecc.point
export type Scalar = sjcl.bn
export type Curve = sjcl.ecc.curve
export type FieldElt = sjcl.bn

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
        // See Section F.2.1.2 at https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-14#appendix-F.2.1.2
        hash: string
        L: number
        Z: number
        c2: string // 2. c2 = sqrt(-Z) in GF(p).
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
                    // c2 = sqrt(-Z) in GF(p).
                    c2: '0x25ac71c31e27646736870398ae7f554d8472e008b3aa2a49d332cbd81bcc3b80'
                }
                break
            case GroupID.P384:
                this.curve = sjcl.ecc.curves.c384
                this.size = 48
                this.hashParams = {
                    hash: 'SHA-384',
                    L: 72,
                    Z: -12,
                    // c2 = sqrt(-Z) in GF(p).
                    c2: '0x2accb4a656b0249c71f0500e83da2fdd7f98e383d68b53871f872fcb9ccb80c53c0de1f8a80f7e1914e2ec69f5a626b3'
                }
                break
            case GroupID.P521:
                this.curve = sjcl.ecc.curves.c521
                this.size = 66
                this.hashParams = {
                    hash: 'SHA-512',
                    L: 98,
                    Z: -4,
                    // c2 = sqrt(-Z) in GF(p).
                    c2: '0x2'
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

    isIdentity(e: Elt): boolean {
        return e.isIdentity
    }

    generator(): Elt {
        return this.curve.G as Elt
    }

    order(): Scalar {
        return this.curve.r as Scalar
    }

    // Serializes an element in uncompressed form.
    private serUnComp(e: Elt): SerializedElt {
        const xy = sjcl.codec.arrayBuffer.fromBits(e.toBits(), false)
        const bytes = new Uint8Array(xy)
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
        const x = sjcl.codec.arrayBuffer.fromBits(e.x.toBits(null), false)
        const bytes = new Uint8Array(x)
        const serElt = new SerializedElt(1 + this.size)

        serElt[0] = 0x02 | (e.y.getLimb(0) & 1)
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
        const array = Array.from(serElt.slice(1))
        const bytes = sjcl.codec.bytes.toBits(array)
        const x = new this.curve.field(sjcl.bn.fromBits(bytes))
        const p = this.curve.field.modulus
        const exp = p.add(new sjcl.bn(1)).halveM().halveM()
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
        const array = Array.from(serElt.slice(1))
        const b = sjcl.codec.bytes.toBits(array)
        const point = this.curve.fromBits(b)
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

        const ab = sjcl.codec.arrayBuffer.fromBits(k.toBits(), false)
        const unpaded = new Uint8Array(ab)
        const serScalar = new SerializedScalar(this.size)
        serScalar.set(unpaded, this.size - unpaded.length)
        return serScalar
    }

    deserializeScalar(serScalar: SerializedScalar): Scalar {
        const array = Array.from(serScalar)
        const k = sjcl.bn.fromBits(sjcl.codec.bytes.toBits(array))
        k.normalize()
        if (k.greaterEquals(this.curve.r)) {
            throw new Error('error deserializing scalar')
        }
        return k as Scalar
    }

    equalScalar(a: Scalar, b: Scalar): boolean {
        return a.equals(b)
    }

    addScalar(a: Scalar, b: Scalar): Scalar {
        const c = a.add(b)
        c.mod(this.curve.r)
        c.normalize()
        return c
    }

    subScalar(a: Scalar, b: Scalar): Scalar {
        const c = a.sub(b).add(this.curve.r)
        c.mod(this.curve.r)
        c.normalize()
        return c
    }

    mulScalar(a: Scalar, b: Scalar): Scalar {
        const c = a.mulmod(b, this.curve.r)
        c.normalize()
        return c
    }

    invScalar(k: Scalar): Scalar {
        return k.inverseMod(this.curve.r)
    }

    isScalarZero(k: Scalar): boolean {
        return k.equals(0)
    }

    static add(e: Elt, f: Elt): Elt {
        return e.toJac().add(f).toAffine() as Elt
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
        const { hash, L } = this.hashParams
        const bytes = await expandXMD(hash, msg, dst, L)
        const array = Array.from(bytes)
        const bitArr = sjcl.codec.bytes.toBits(array)
        const s = sjcl.bn.fromBits(bitArr).mod(this.curve.r)
        return s as Scalar
    }

    async hashToGroup(msg: Uint8Array, dst: Uint8Array): Promise<Elt> {
        const u = await this.hashToField(msg, dst, 2)
        const Q0 = this.sswu(u[0])
        const Q1 = this.sswu(u[1])
        return Q0.add(Q1.toAffine()).toAffine() as Elt
    }

    private async hashToField(
        msg: Uint8Array,
        dst: Uint8Array,
        count: number
    ): Promise<FieldElt[]> {
        const { hash, L } = this.hashParams
        const bytes = await expandXMD(hash, msg, dst, count * L)
        const u = new Array<FieldElt>(count)
        for (let i = 0; i < count; i++) {
            const j = i * L
            const array = Array.from(bytes.slice(j, j + L))
            const bitArr = sjcl.codec.bytes.toBits(array)
            u[i as number] = new this.curve.field(sjcl.bn.fromBits(bitArr))
        }
        return u
    }

    private sswu(u: FieldElt): sjcl.ecc.pointJac {
        // Simplified SWU method.
        // Appendix F.2 of draft-irtf-cfrg-hash-to-curve-14
        // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-14#appendix-F.2
        const {
            a: A,
            b: B,
            field: { modulus: p }
        } = this.curve
        const Z = new this.curve.field(this.hashParams.Z)
        const c2 = new this.curve.field(this.hashParams.c2) // c2 = sqrt(-Z)
        const c1 = p.sub(new sjcl.bn(3)).halveM().halveM() // c1 = (p-3)/4
        const zero = new this.curve.field(0)
        const one = new this.curve.field(1)

        function sgn(x: FieldElt): number {
            x.fullReduce()
            return x.getLimb(0) & 1
        }
        function cmov(x: FieldElt, y: FieldElt, b: boolean): FieldElt {
            return b ? y : x
        }
        // Input: u and v, elements of F, where v != 0.
        // Output: (isQR, root), where
        //   isQR = True  and root = sqrt(u / v) if (u / v) is square in F, and
        //   isQR = False and root = sqrt(Z * (u / v)) otherwise.
        function sqrt_ratio_3mod4(u: FieldElt, v: FieldElt): { isQR: boolean; root: FieldElt } {
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

        const point = new sjcl.ecc.pointJac(this.curve, x, y, z)
        if (!point.isValid()) {
            throw new Error('point not in curve')
        }
        return point
    }
}
