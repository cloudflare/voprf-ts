// This file can be easily written over in CI
import { CryptoSjcl } from './cryptoSjcl.js'

// See CryptoProviderArg used as ...rest type pervasively
// We can set this to `true` to check that the internal code and
// tests are properly passing around the provider object everywhere.
// We can set it to `false` to not require the arg and let it
// default to `DEFAULT_CRYPTO_PROVIDER`
export const CRYPTO_PROVIDER_ARG_REQUIRED: boolean = false

// Of course, this means that using the api with a non default provider
// is not very nice, but it does allow the facade api to avoid the
// use of a global, and potentially allow the use of multiple providers
// in a single process, picking and choosing a provider for group support.
// You can use setCryptoProvider if you want to use the non-facade api with a
// non-default provider and not need to pass everything around.
// Single provider per process limitations apply.
export const DEFAULT_CRYPTO_PROVIDER = CryptoSjcl
