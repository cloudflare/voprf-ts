// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import Benchmark from 'benchmark'
import { Group } from '../src/index.js'

function asyncFn(call: CallableFunction) {
    return {
        defer: true,
        async fn(df: Benchmark.Deferred) {
            await call()
            df.resolve()
        }
    }
}

export async function benchGroup(bs: Benchmark.Suite) {
    const te = new TextEncoder()
    const msg = te.encode('msg')
    const dst = te.encode('dst')

    for (const id of Object.values(Group.ID)) {
        const gg = new Group(id)
        const k = await gg.randomScalar()
        const P = gg.mulGen(k)
        const Q = P.mul(k)

        const prefix = gg.id + '/'

        bs.add(prefix + 'add         ', () => P.add(Q))
        bs.add(prefix + 'mulgen      ', () => gg.mulGen(k))
        bs.add(prefix + 'mul         ', () => P.mul(k))
        bs.add(
            prefix + 'hashToScalar',
            asyncFn(() => gg.hashToScalar(msg, dst))
        )
        bs.add(
            prefix + 'hashToGroup ',
            asyncFn(() => gg.hashToGroup(msg, dst))
        )
    }
}
