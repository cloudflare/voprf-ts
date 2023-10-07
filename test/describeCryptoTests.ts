import { CryptoNoble } from '../src/cryptoNoble.js'
import { type GroupCons } from '../src/index.js'
import { CryptoSjcl } from '../src/cryptoSjcl.js'
import { Crypto } from '../src/crypto.js'

const groupConsMatch = process.env.CRYPTO_PROVIDER

export const testProviders = (
    [
        ['noble', CryptoNoble],
        ['sjcl', CryptoSjcl]
    ] as const
).filter(([name]) => {
    return !groupConsMatch || name === groupConsMatch
})

export function describeCryptoTests(declare: (group: GroupCons) => void) {
    describe.each(testProviders)(`Crypto-%s`, (_groupName, provider) => {
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
