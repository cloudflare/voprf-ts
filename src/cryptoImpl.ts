import type { CryptoProvider, HashID } from './cryptoTypes.js'
import { CryptoSjcl } from './cryptoSjcl.js'

export const DEFAULT_CRYPTO_PROVIDER = CryptoSjcl

/**
 * The `CryptoProviderIntermediary` class serves as an intermediary for utilizing a cryptographic provider.
 * It implements the `CryptoProvider` interface, encapsulating a `CryptoProvider` instance
 * which can be overridden via the `provider` field. This design allows for flexible
 * substitution of cryptographic providers while ensuring adherence to the `CryptoProvider`
 * interface contract.
 *
 * The `CryptoImpl` object, instantiated from `CryptoProviderIntermediary` with a default provider, acts as the
 * accessible point for cryptographic operations within the library. Users can override the
 * default cryptographic provider by setting a different provider to the `CryptoImpl.provider` field.
 *
 * Usage:
 * ```javascript
 * import { CryptoImpl } from '@cloudflare/voprf-ts';
 * import { YourCryptoProvider } from './your-crypto-provider-file.js';
 *
 * // Override the default crypto provider
 * CryptoImpl.provider = YourCryptoProvider;
 *
 * // Now CryptoImpl will use YourCryptoProvider for cryptographic operations
 * ```
 */
class CryptoProviderIntermediary implements CryptoProvider {
    constructor(public provider: CryptoProvider) {}

    get Group() {
        return this.provider.Group
    }

    get name() {
        return this.provider.name
    }

    hash(hashID: HashID, input: Uint8Array): Promise<Uint8Array> {
        return this.provider.hash(hashID, input)
    }
}

// Because Crypto is already a global, we name this CryptoImpl
export const CryptoImpl = new CryptoProviderIntermediary(DEFAULT_CRYPTO_PROVIDER)
