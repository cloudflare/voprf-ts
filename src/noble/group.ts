// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { bytesToNumberBE, bytesToNumberLE } from '@noble/curves/abstract/utils'

import {
    type Deserializer,
    GROUP,
    type Group,
    type GroupCache,
    type GroupID
} from '../groupTypes.js'
import type { GroupParams } from './types.js'
import { ScalarNb } from './scalar.js'
import { EltNb } from './element.js'
import { getParams } from './params.js'

export class GroupNb implements Group {
    static readonly supportedGroups: GroupID[] = [
        GROUP.RISTRETTO255,
        GROUP.DECAF448,
        GROUP.P256,
        GROUP.P384,
        GROUP.P521
    ]

    static readonly #cache: GroupCache = {}

    static get(gid: GroupID): Group {
        let { [gid]: group } = this.#cache
        if (!group) {
            group = new this(gid)
            Object.assign(this.#cache, { gid: group })
        }

        return group
    }

    public readonly params: GroupParams
    public readonly id: GroupID

    constructor(gid: GroupID) {
        this.params = getParams(gid)
        this.id = gid
    }

    bytesToNumber(bytes: Uint8Array) {
        return this.params.isEdwards ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes)
    }

    newScalar(): ScalarNb {
        return ScalarNb.create(this)
    }

    newElt(): EltNb {
        return this.identity()
    }

    identity(): EltNb {
        return EltNb.create(this)
    }

    generator(): EltNb {
        return EltNb.gen(this)
    }

    mulGen(s: ScalarNb): EltNb {
        return EltNb.gen(this).mul(s)
    }

    randomScalar(): Promise<ScalarNb> {
        const msg = crypto.getRandomValues(new Uint8Array(this.params.scalar.size))
        return Promise.resolve(ScalarNb.hash(this, msg, new Uint8Array()))
    }

    hashToGroup(msg: Uint8Array, dst: Uint8Array): Promise<EltNb> {
        return Promise.resolve(EltNb.hash(this, msg, dst))
    }

    hashToScalar(msg: Uint8Array, dst: Uint8Array): Promise<ScalarNb> {
        return Promise.resolve(ScalarNb.hash(this, msg, dst))
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
