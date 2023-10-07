import { CryptoNoble } from '../src/cryptoNoble.js'
import { type GroupCons } from '../src/index.js'
import { CryptoSjcl } from '../src/cryptoSjcl.js'
import { Crypto } from '../src/crypto.js'

const cryptoProviderMatch = process.env.CRYPTO_PROVIDER
const allProviders = [CryptoNoble, CryptoSjcl]
export const testProviders = allProviders.filter(
    (provider) => !cryptoProviderMatch || provider.name === cryptoProviderMatch
)

export function describeCryptoTests(declare: (group: GroupCons) => void) {
    describe.each(testProviders)(`Crypto-%s`, (provider) => {
        // Will run before other beforeAll hooks (see vectors.test.ts)
        beforeAll(() => {
            Crypto.provider = provider
        })
        // Will run before other tests
        beforeEach(() => {
            Crypto.provider = provider
        })
        Crypto.provider = provider
        declare(provider.Group)
    })
}
