// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

export const GROUP = {
    // P256_XMD:SHA-256_SSWU_RO_
    P256: 'P-256',
    // P384_XMD:SHA-384_SSWU_RO_
    P384: 'P-384',
    // P521_XMD:SHA-512_SSWU_RO_
    P521: 'P-521',
    // ristretto255_XMD:SHA-512_R255MAP_RO_
    RISTRETTO255: 'ristretto255',
    // decaf448_XOF:SHAKE256_D448MAP_RO_
    DECAF448: 'decaf448'
} as const

export type GroupID = (typeof GROUP)[keyof typeof GROUP]

export function errBadGroup(X: string) {
    return new Error(`group: bad group name ${X}.`)
}

export interface Scalar {
    g: Group

    isEqual(s: Scalar): boolean

    isZero(): boolean

    add(s: Scalar): Scalar

    sub(s: Scalar): Scalar

    mul(s: Scalar): Scalar

    inv(): Scalar

    serialize(): Uint8Array
}

export interface Elt {
    g: Group

    isIdentity(): boolean

    isEqual(a: Elt): boolean

    neg(): Elt

    add(a: Elt): Elt

    mul(s: Scalar): Elt

    mul2(k1: Scalar, a: Elt, k2: Scalar): Elt

    serialize(compressed?: boolean): Uint8Array
}

export interface Deserializer<T> {
    size(compressed?: boolean): number

    deserialize(b: Uint8Array): T
}

export interface SerializationHelpers {
    desElt(bytes: Uint8Array): Elt

    desScalar(bytes: Uint8Array): Scalar

    eltDes: Deserializer<Elt>
    scalarDes: Deserializer<Scalar>

    eltSize(compressed?: boolean): number

    scalarSize(): number
}

export interface Group extends SerializationHelpers {
    id: GroupID

    newScalar(): Scalar

    newElt(): Elt

    identity(): Elt

    generator(): Elt

    mulGen(s: Scalar): Elt

    randomScalar(): Promise<Scalar>

    hashToGroup(msg: Uint8Array, dst: Uint8Array): Promise<Elt>

    hashToScalar(msg: Uint8Array, dst: Uint8Array): Promise<Scalar>
}

export interface GroupCons {
    get(id: GroupID): Group
    supportedGroups: Array<GroupID>
}

export type GroupCache = Partial<Record<GroupID, Group>>
