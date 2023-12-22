import type { Mode, ModeID, SuiteID, Server, Client, KeyManager, ModeParams } from '../types.js'
import type { Group } from '../../groupTypes.js'
import type { CryptoProvider } from '../../cryptoTypes.js'
import { ServerImpl } from './ServerImpl.js'
import { ClientImpl } from './ClientImpl.js'
import { KeyManagerImpl } from './KeyManagerImpl.js'
import { getOprfParams } from '../../oprf.js'

export class ModeImpl implements Mode {
    keys: KeyManager
    params: ModeParams

    constructor(
        public mode: ModeID,
        public suite: SuiteID,
        public group: Group,
        public crypto: CryptoProvider
    ) {
        this.keys = new KeyManagerImpl(...this.getBaseArgs())
        this.params = this.getParams()
    }

    private getParams() {
        const [suite, group, hash, size] = getOprfParams(this.suite)
        const scalar = this.group.scalarSize()
        const elt = this.group.eltSize()
        return {
            mode: this.mode,
            suite,
            group,
            hash,
            sizes: {
                elt: elt,
                output: size,
                proof: scalar * 2,
                scalar
            }
        }
    }

    makeServer(privateKey: Uint8Array): Server {
        return new ServerImpl(privateKey, ...this.getBaseArgs())
    }

    makeClient(publicKey?: Uint8Array): Client {
        return new ClientImpl(publicKey, ...this.getBaseArgs())
    }

    private getBaseArgs() {
        return [this.mode, this.suite, this.crypto, this.group] as const
    }
}
