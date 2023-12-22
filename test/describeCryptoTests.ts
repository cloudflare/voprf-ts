import { CryptoNoble } from '../src/cryptoNoble.js'
import {
    type CryptoProvider,
    getOprfParams,
    getSupportedSuites,
    type GroupID
} from '../src/index.js'
import { CryptoSjcl } from '../src/cryptoSjcl.js'

const cryptoProviderMatch = process.env.CRYPTO_PROVIDER
const allProviders = [CryptoNoble, CryptoSjcl]
export const testProviders = allProviders
    .filter((provider) => !cryptoProviderMatch || provider.id === cryptoProviderMatch)
    .map((p) => [p.id, p] as const)

export function describeCryptoTests(
    declare: (args: {
        provider: CryptoProvider
        supportedSuites: Array<ReturnType<typeof getOprfParams>>
        supportedGroups: GroupID[]
    }) => void
) {
    describe.each(testProviders)(`CryptoProvider({id: '%s'})`, (_, provider) => {
        declare({
            provider: provider,
            supportedSuites: getSupportedSuites(provider.Group).map(getOprfParams),
            supportedGroups: provider.Group.supportedGroups
        })
    })
}
