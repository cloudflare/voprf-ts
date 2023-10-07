import type { CryptoProvider, HashID } from './cryptoTypes.js'
import { CryptoSjcl } from './cryptoSjcl.js'

class CryptoImpl implements CryptoProvider {
    constructor(public provider: CryptoProvider) {}

    get Group() {
        return this.provider.Group
    }

    hash(hashID: HashID, input: Uint8Array): Promise<Uint8Array> {
        return this.provider.hash(hashID, input)
    }
}

// There's already a Crypto global which makes auto imports fail
export const Crypto = new CryptoImpl(CryptoSjcl)
