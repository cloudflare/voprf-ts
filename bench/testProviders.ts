import { CryptoNoble } from '../src/cryptoNoble.js'
import { CryptoSjcl } from '../src/cryptoSjcl.js'

const allProviders = [CryptoNoble, CryptoSjcl]
const providerMatch = process.env.CRYPTO_PROVIDER

export function getCryptoProviders() {
    const names = allProviders.map((p) => p.name)
    const testProviders = allProviders.filter(
        (provider) => !providerMatch || provider.name === providerMatch
    )
    if (testProviders.length === 0) {
        throw new Error(`no CryptoProvider with name === ${providerMatch} among [${names}]`)
    }
    return testProviders
}
