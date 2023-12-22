import { OprfBaseImpl } from './OprfBaseImpl.js'
import type { KeySizes, KeyPair, KeyManager } from '../types.js'
import {
    getKeySizes,
    validatePrivateKey,
    validatePublicKey,
    randomPrivateKey,
    derivePrivateKey,
    generatePublicKey,
    generateKeyPair,
    deriveKeyPair
} from '../../keys.js'

export class KeyManagerImpl extends OprfBaseImpl implements KeyManager {
    sizes(): KeySizes {
        const internal = getKeySizes(this.suite, this.crypto)
        return { publicKey: internal.Npk, privateKey: internal.Nsk }
    }

    validatePrivate(privateKey: Uint8Array): boolean {
        return validatePrivateKey(this.suite, privateKey, this.crypto)
    }

    validatePublic(publicKey: Uint8Array): boolean {
        return validatePublicKey(this.suite, publicKey, this.crypto)
    }

    randomPrivate(): Promise<Uint8Array> {
        return randomPrivateKey(this.suite, this.crypto)
    }

    derivePrivate(seed: Uint8Array, info: Uint8Array): Promise<Uint8Array> {
        return derivePrivateKey(this.mode, this.suite, seed, info, this.crypto)
    }

    generatePublic(privateKey: Uint8Array): Uint8Array {
        return generatePublicKey(this.suite, privateKey, this.crypto)
    }

    generatePair(): Promise<KeyPair> {
        return generateKeyPair(this.suite, this.crypto)
    }

    derivePair(seed: Uint8Array, info: Uint8Array): Promise<KeyPair> {
        return deriveKeyPair(this.mode, this.suite, seed, info, this.crypto)
    }
}
