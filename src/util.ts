// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

export function joinAll(a: Uint8Array[]): Uint8Array {
    let size = 0
    for (let i = 0; i < a.length; i++) {
        size += a[i as number].length
    }
    const ret = new Uint8Array(new ArrayBuffer(size))
    for (let i = 0, offset = 0; i < a.length; i++) {
        ret.set(a[i as number], offset)
        offset += a[i as number].length
    }
    return ret
}

export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
    if (a.length !== b.length || a.length === 0) {
        throw new Error('arrays of different length')
    }
    const n = a.length
    const c = new Uint8Array(n)
    for (let i = 0; i < n; i++) {
        c[i as number] = a[i as number] ^ b[i as number]
    }
    return c
}

export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length || a.length === 0) {
        return false
    }
    const n = a.length
    let c = 0
    for (let i = 0; i < n; i++) {
        c |= a[i as number] ^ b[i as number]
    }
    return c === 0
}

export function to16bits(n: number): Uint8Array {
    if (!(n >= 0 && n < 0xffff)) {
        throw new Error('number bigger than 2^16')
    }
    return new Uint8Array([(n >> 8) & 0xff, n & 0xff])
}

export function toU16LenPrefix(b: Uint8Array): Uint8Array[] {
    return [to16bits(b.length), b]
}

export function fromU16LenPrefix(b: Uint8Array): { head: Uint8Array; tail: Uint8Array } {
    if (b.length < 2) {
        throw new Error(`buffer shorter than expected`)
    }
    const n = (b[0] << 8) | b[1]
    if (b.length < 2 + n) {
        throw new Error(`buffer shorter than expected`)
    }
    const head = b.subarray(2, 2 + n)
    const tail = b.subarray(2 + n)
    return { head, tail }
}

export function checkSize<U>(
    x: Uint8Array,
    T: { name: string; size: (x: U) => number },
    u: U
): void | never {
    if (x.length < T.size(u)) {
        throw new Error(`error deserializing ${T.name}: buffer shorter than expected`)
    }
}
