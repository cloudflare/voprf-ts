// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

export const GroupIDs = {
    P256: 'P-256',
    P384: 'P-384',
    P521: 'P-521'
} as const

export type GroupID = (typeof GroupIDs)[keyof typeof GroupIDs]

export function errBadGroup(X: string) {
    return new Error(`group: bad group name ${X}.`)
}

export function getGroupID(id: string): GroupID {
    switch (id) {
        case 'P-256':
            return GroupIDs.P256
        case 'P-384':
            return GroupIDs.P384
        case 'P-521':
            return GroupIDs.P521
        default:
            throw errBadGroup(id)
    }
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

export interface ScalarCons {
    size(g: Group): number
    deserialize(g: Group, bytes: Uint8Array): Scalar
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

export interface EltCons {
    // Used by serializer
    size(g: Group, compressed?: boolean): number
    deserialize(g: Group, bytes: Uint8Array): Elt
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
    size: number

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
    new (id: GroupID): Group
    ID: typeof GroupIDs
    getID: typeof getGroupID
    Elt: EltCons
    Scalar: ScalarCons
}
