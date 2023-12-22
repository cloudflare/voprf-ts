import type { OprfApi, ModeID, MakeModeParams, Mode } from '../types.js'
import type { CryptoProvider } from '../../cryptoTypes.js'
import { SUITE, MODE } from '../../consts.js'
import { getOprfParams } from '../../oprf.js'
import { ModeImpl } from './ModeImpl.js'
import { getCryptoProvider } from '../../cryptoImpl.js'

export class OprfApiImpl implements OprfApi {
    constructor(private _crypto?: CryptoProvider) {}

    get crypto() {
        return this._crypto ?? getCryptoProvider()
    }

    Suite = SUITE
    Mode = MODE

    withConfig(config: { crypto: CryptoProvider }): OprfApi {
        return new OprfApiImpl(config.crypto)
    }

    makeMode<M extends ModeID>(params: MakeModeParams<M>): Mode<M> {
        const group = this.crypto.Group.get(getOprfParams(params.suite)[1])
        return new ModeImpl(params.mode, params.suite, group, this.crypto) as Mode as Mode<M>
    }
}
