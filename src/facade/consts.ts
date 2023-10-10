export const MODE = {
    // TODO: use string
    // Otherwise the type inference shown in IDES is for Client<?, ?> is Client<2, 'P256-SHA256'>
    // Could easily create some kind of utils to convert numbers to MODE
    // in any case, you already need to faff around
    // see: vector tests
    // const txtMode = Object.entries(Oprf.Mode)[mode as number][0]
    OPRF: 0, // 'oprf', // 0,
    VOPRF: 1, // 'voprf', // 1,
    POPRF: 2 // 'poprf' // 2
} as const

export type ModeOprf = typeof MODE.OPRF
export type ModeVoprf = typeof MODE.VOPRF
export type ModePoprf = typeof MODE.POPRF

export const SUITE = {
    P256_SHA256: 'P256-SHA256',
    P384_SHA384: 'P384-SHA384',
    P521_SHA512: 'P521-SHA512',
    RISTRETTO255_SHA512: 'ristretto255-SHA512',
    DECAF448_SHAKE256: 'decaf448-SHAKE256'
} as const
