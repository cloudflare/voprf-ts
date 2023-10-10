import { CryptoNoble } from '../src/cryptoNoble.js'
import { getSupportedSuites, type GroupID, type SuiteID } from '../src/index.js'
import { CryptoSjcl } from '../src/cryptoSjcl.js'
import { CryptoImpl } from '../src/cryptoImpl.js'

const cryptoProviderMatch = process.env.CRYPTO_PROVIDER
const allProviders = [CryptoNoble, CryptoSjcl]
export const testProviders = allProviders
    .filter((provider) => !cryptoProviderMatch || provider.name === cryptoProviderMatch)
    .map((p) => [p.name, p] as const)

export function describeCryptoTests(
    declare: (args: { supportedSuites: SuiteID[]; supportedGroups: GroupID[] }) => void
) {
    describe.each(testProviders)(`CryptoProvider({name: '%s'})`, (_, provider) => {
        // Will run before other beforeAll hooks (see vectors.test.ts)
        beforeAll(() => {
            CryptoImpl.provider = provider
        })
        // Will run before other tests
        beforeEach(() => {
            CryptoImpl.provider = provider
        })
        CryptoImpl.provider = provider
        declare({
            supportedSuites: getSupportedSuites(provider.Group),
            supportedGroups: provider.Group.supportedGroups
        })
    })
}
