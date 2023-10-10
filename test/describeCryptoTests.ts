import { CryptoNoble } from '../src/cryptoNoble.js'
import {
    type CryptoProvider,
    getSupportedSuites,
    type GroupID,
    type SuiteID
} from '../src/index.js'
import { CryptoSjcl } from '../src/cryptoSjcl.js'

const cryptoProviderMatch = process.env.CRYPTO_PROVIDER
const allProviders = [CryptoNoble, CryptoSjcl]
export const testProviders = allProviders
    .filter((provider) => !cryptoProviderMatch || provider.name === cryptoProviderMatch)
    .map((p) => [p.name, p] as const)

export function describeCryptoTests(
    declare: (args: {
        cryptoProvider: CryptoProvider
        supportedSuites: SuiteID[]
        supportedGroups: GroupID[]
    }) => void
) {
    describe.each(testProviders)(`CryptoProvider({name: '%s'})`, (_, provider) => {
        // Will run before other beforeAll hooks (see vectors.test.ts)
        declare({
            cryptoProvider: provider,
            supportedSuites: getSupportedSuites(provider.Group),
            supportedGroups: provider.Group.supportedGroups
        })
    })
}
