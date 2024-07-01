import { getOprfParams, type SuiteID } from './oprf.js'
import type { CryptoProvider } from './cryptoTypes.js'
import { CRYPTO_PROVIDER_ARG_REQUIRED, DEFAULT_CRYPTO_PROVIDER } from './buildSettings.js'
import type { GroupID } from './groupTypes.js'

const REQUIRED = CRYPTO_PROVIDER_ARG_REQUIRED
let configured = DEFAULT_CRYPTO_PROVIDER

type OptionalArg = [cryptoProvider?: CryptoProvider]
type RequiredArg = [CryptoProvider]

export type CryptoProviderArg = typeof REQUIRED extends true ? RequiredArg : OptionalArg

export function getCrypto(arg: CryptoProviderArg) {
    const [provider] = arg
    if (!provider && REQUIRED) {
        throw new Error(`Undefined crypto arg`)
    }

    return provider ?? configured
}

export function getGroup(groupID: GroupID, arg: CryptoProviderArg) {
    const provider = getCrypto(arg)
    return provider.Group.get(groupID)
}

export function getSuiteGroup(suite: SuiteID, arg: CryptoProviderArg) {
    return getGroup(getOprfParams(suite)[1], arg)
}

// This way the `old` api can be used
export function setCryptoProvider(provider: CryptoProvider) {
    configured = provider
}

export function getCryptoProvider() {
    return configured
}
