// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { Blind, Blinded, Evaluation, Oprf } from './oprf.js'

import { Group } from './group.js'

export class OPRFClient extends Oprf {
    async randomBlinder(): Promise<{ scalar: unknown; blind: Blind }> {
        const scalar = await this.params.gg.randomScalar(),
            blind = new Blind(this.params.gg.serializeScalar(scalar))
        return { scalar, blind }
    }

    async blind(input: Uint8Array): Promise<{ blind: Blind; blindedElement: Blinded }> {
        const { scalar, blind } = await this.randomBlinder(),
            dst = Oprf.getHashToGroupDST(this.params.id),
            P = await this.params.gg.hashToGroup(input, dst),
            Q = Group.mul(scalar, P),
            blindedElement = new Blinded(this.params.gg.serialize(Q))
        return { blind, blindedElement }
    }

    finalize(
        input: Uint8Array,
        info: Uint8Array,
        blind: Blind,
        evaluation: Evaluation
    ): Promise<Uint8Array> {
        const blindScalar = this.params.gg.deserializeScalar(blind),
            blindScalarInv = this.params.gg.invScalar(blindScalar),
            Z = this.params.gg.deserialize(evaluation),
            N = Group.mul(blindScalarInv, Z),
            unblinded = this.params.gg.serialize(N)
        return this.coreFinalize(input, info, unblinded)
    }
}
