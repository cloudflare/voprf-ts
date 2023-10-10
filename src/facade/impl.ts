/* eslint-disable @typescript-eslint/no-unused-vars */
// noinspection JSUnusedLocalSymbols
import * as assert from 'assert'

import type { Client, KeyPair, KeySizes, Mode, ModeID, OprfApi, Server, SuiteID } from './types.js'
import type { CryptoProvider } from '../cryptoTypes.js'
import type { Group } from '../groupTypes.js'

import { MODE, type ModeOprf, type ModePoprf, type ModeVoprf, SUITE } from './consts.js'
import { OPRFClient, POPRFClient, VOPRFClient } from '../client.js'
import { OPRFServer, POPRFServer, VOPRFServer } from '../server.js'

import {
    deriveKeyPair,
    derivePrivateKey,
    generateKeyPair,
    generatePublicKey,
    getKeySizes,
    randomPrivateKey,
    validatePrivateKey,
    validatePublicKey
} from '../keys.js'
import { getOprfParams } from '../oprf.js'
import { DEFAULT_CRYPTO_PROVIDER } from '../cryptoImpl.js'

class ModeImpl implements Mode<ModeID, SuiteID> {
    constructor(
        public modeID: ModeID,
        public suiteID: SuiteID,
        public gg: Group
    ) {}

    makeServer(privateKey: Uint8Array): Server {
        switch (this.modeID) {
            case MODE.OPRF:
                return new OPRFServer(this.suiteID, privateKey)
            case MODE.POPRF:
                return new POPRFServer(this.suiteID, privateKey)
            case MODE.VOPRF:
                return new VOPRFServer(this.suiteID, privateKey)
            default:
                throw new Error(`Unsupported mode: ${this.modeID}`)
        }
    }

    makeClient(): Client<ModeOprf>
    makeClient(publicKey: Uint8Array): Client<ModePoprf | ModeVoprf>
    makeClient(publicKey?: Uint8Array): Client {
        switch (this.modeID) {
            case MODE.OPRF:
                return new OPRFClient(this.suiteID)
            case MODE.POPRF:
                assert.ok(publicKey, 'public key required')
                return new POPRFClient(this.suiteID, publicKey)
            case MODE.VOPRF:
                assert.ok(publicKey, 'public key required')
                return new VOPRFClient(this.suiteID, publicKey)
            default:
                throw new Error(`Unsupported mode: ${this.modeID}`)
        }
    }

    getKeySizes(): KeySizes {
        const internal = getKeySizes(this.suiteID)
        return { publicKey: internal.Npk, privateKey: internal.Nsk }
    }

    validatePrivateKey(privateKey: Uint8Array): boolean {
        return validatePrivateKey(this.suiteID, privateKey)
    }

    validatePublicKey(publicKey: Uint8Array): boolean {
        return validatePublicKey(this.suiteID, publicKey)
    }

    randomPrivateKey(): Promise<Uint8Array> {
        return randomPrivateKey(this.suiteID)
    }

    derivePrivateKey(seed: Uint8Array, info: Uint8Array): Promise<Uint8Array> {
        return derivePrivateKey(this.modeID, this.suiteID, seed, info)
    }

    generatePublicKey(privateKey: Uint8Array): Uint8Array {
        return generatePublicKey(this.suiteID, privateKey)
    }

    generateKeyPair(): Promise<KeyPair> {
        return generateKeyPair(this.suiteID)
    }

    deriveKeyPair(seed: Uint8Array, info: Uint8Array): Promise<KeyPair> {
        return deriveKeyPair(this.modeID, this.suiteID, seed, info)
    }
}

class OprfApiImpl implements OprfApi {
    constructor(private _crypto: CryptoProvider) {}

    Suite = SUITE
    Mode = MODE

    withConfiguration(config: { crypto: CryptoProvider }): OprfApi {
        return new OprfApiImpl(config.crypto)
    }

    makeMode<M extends ModeID, S extends SuiteID>(params: { mode: M; suite: S }): Mode<M, S> {
        const gid = getOprfParams(params.suite)[1]
        const gg = this.crypto.Group.fromID(gid)
        const modeImpl = new ModeImpl(params.mode, params.suite, gg) as Mode<ModeID, SuiteID>
        return modeImpl as Mode<M, S>
    }

    get crypto() {
        return this._crypto
    }
}

export const OprfTs = new OprfApiImpl(DEFAULT_CRYPTO_PROVIDER)
