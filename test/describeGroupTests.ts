import { CryptoNoble } from '../src/cryptoNoble.js'
import { type GroupCons, Oprf } from '../src/index.js'
import { CryptoSjcl } from '../src/cryptoSjcl.js'

const groupConsMatch = process.env.GROUP_CONS

export const testProviders = (
    [
        ['noble', CryptoNoble],
        ['sjcl', CryptoSjcl]
    ] as const
).filter(([name]) => {
    return !groupConsMatch || name === groupConsMatch
})

export function describeGroupTests(declare: (group: GroupCons) => void) {
    describe.each(testProviders)(`Group-%s`, (_groupName, provider) => {
        // Will run before other beforeAll hooks (see vectors.test.ts)
        beforeAll(() => {
            Oprf.Crypto = provider
        })

        // Will run before other tests
        beforeEach(() => {
            Oprf.Crypto = provider
        })

        Oprf.Crypto = provider
        declare(provider.Group)
    })
}
