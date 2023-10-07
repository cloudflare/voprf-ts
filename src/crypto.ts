import type { CryptoProvider, HashID } from './cryptoTypes.js'
import { CryptoSjcl } from './cryptoSjcl.js'

export const DEFAULT_CRYPTO_PROVIDER = CryptoSjcl

/**
 * The `CryptoImpl` class serves as an intermediary for utilizing a cryptographic provider.
 * It implements the `CryptoProvider` interface, encapsulating a `CryptoProvider` instance
 * which can be overridden via the `provider` field. This design allows for flexible
 * substitution of cryptographic providers while ensuring adherence to the `CryptoProvider`
 * interface contract.
 *
 * The `Crypto` object, instantiated from `CryptoImpl` with a default provider, acts as the
 * accessible point for cryptographic operations within the library. Users can override the
 * default cryptographic provider by setting a different provider to the `Crypto.provider` field.
 *
 * Usage:
 * ```javascript
 * import { Crypto } from './path-to-this-file';
 * import { YourCryptoProvider } from './your-crypto-provider-file';
 *
 * // Override the default crypto provider
 * Crypto.provider = YourCryptoProvider;
 *
 * // Now Crypto will use YourCryptoProvider for cryptographic operations
 * ```
 */
class CryptoImpl implements CryptoProvider {
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

export const Crypto = new CryptoImpl(DEFAULT_CRYPTO_PROVIDER)
