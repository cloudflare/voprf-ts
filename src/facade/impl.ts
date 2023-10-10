/* eslint-disable @typescript-eslint/no-unused-vars,@typescript-eslint/no-explicit-any */
// noinspection JSUnusedLocalSymbols
import * as assert from 'assert'

import type { Client, KeyPair, KeySizes, Mode, ModeID, OprfApi, Server, SuiteID } from './types.js'
import type { CryptoProvider } from '../cryptoTypes.js'

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
import type { Group } from '../groupTypes.js'

class ModeImpl implements Mode {
    constructor(
        public modeID: ModeID,
        public suiteID: SuiteID,
        public gg: Group,
        public crypto: CryptoProvider
    ) {}

    makeServer(privateKey: Uint8Array): Server {
        return this._makeServer(privateKey)
    }

    makeClient(): Client<ModeOprf>

    makeClient(publicKey: Uint8Array): Client<ModePoprf | ModeVoprf>
    makeClient(publicKey?: Uint8Array): Client {
        return this._makeClient(publicKey)
    }

    private _makeServer(privateKey: Uint8Array) {
        switch (this.modeID) {
            case MODE.OPRF:
                return new OPRFServer(this.suiteID, privateKey, this.crypto)
            case MODE.POPRF:
                return new POPRFServer(this.suiteID, privateKey, this.crypto)
            case MODE.VOPRF:
                return new VOPRFServer(this.suiteID, privateKey, this.crypto)
            default:
                throw new Error(`Unsupported mode: ${this.modeID}`)
        }
    }

    private _makeClient(publicKey: Uint8Array | undefined) {
        switch (this.modeID) {
            case MODE.OPRF:
                return new OPRFClient(this.suiteID, this.crypto)
            case MODE.POPRF:
                assert.ok(publicKey, 'public key required')
                return new POPRFClient(this.suiteID, publicKey, this.crypto)
            case MODE.VOPRF:
                assert.ok(publicKey, 'public key required')
                return new VOPRFClient(this.suiteID, publicKey, this.crypto)
            default:
                throw new Error(`Unsupported mode: ${this.modeID}`)
        }
    }

    getKeySizes(): KeySizes {
        const internal = getKeySizes(this.suiteID)
        return { publicKey: internal.Npk, privateKey: internal.Nsk }
    }

    validatePrivateKey(privateKey: Uint8Array): boolean {
        return validatePrivateKey(this.suiteID, privateKey, this.crypto)
    }

    validatePublicKey(publicKey: Uint8Array): boolean {
        return validatePublicKey(this.suiteID, publicKey, this.crypto)
    }

    randomPrivateKey(): Promise<Uint8Array> {
        return randomPrivateKey(this.suiteID, this.crypto)
    }

    derivePrivateKey(seed: Uint8Array, info: Uint8Array): Promise<Uint8Array> {
        return derivePrivateKey(this.modeID, this.suiteID, seed, info, this.crypto)
    }

    generatePublicKey(privateKey: Uint8Array): Uint8Array {
        return generatePublicKey(this.suiteID, privateKey, this.crypto)
    }

    generateKeyPair(): Promise<KeyPair> {
        return generateKeyPair(this.suiteID, this.crypto)
    }

    deriveKeyPair(seed: Uint8Array, info: Uint8Array): Promise<KeyPair> {
        return deriveKeyPair(this.modeID, this.suiteID, seed, info, this.crypto)
    }
}

class OprfApiImpl implements OprfApi {
    constructor(public crypto: CryptoProvider) {}

    Suite = SUITE
    Mode = MODE

    withConfig(config: { crypto: CryptoProvider }): OprfApi {
        return new OprfApiImpl(config.crypto)
    }

    makeMode<M extends ModeID, S extends SuiteID>(params: { mode: M; suite: S }): Mode<M, S> {
        const gid = getOprfParams(params.suite)[1]
        const gg = this.crypto.Group.fromID(gid)
        const impl = new ModeImpl(params.mode, params.suite, gg, this.crypto)
        const modeUp = impl as Mode
        return modeUp as Mode<M, S>
    }
}

export const Oprf = new OprfApiImpl(DEFAULT_CRYPTO_PROVIDER)
