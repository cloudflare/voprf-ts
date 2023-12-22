export const MODE = {
    OPRF: 0,
    VOPRF: 1,
    POPRF: 2
} as const

export const SUITE = {
    P256_SHA256: 'P256-SHA256',
    P384_SHA384: 'P384-SHA384',
    P521_SHA512: 'P521-SHA512',
    RISTRETTO255_SHA512: 'ristretto255-SHA512',
    DECAF448_SHAKE256: 'decaf448-SHAKE256'
} as const

export const LABELS = {
    Version: 'OPRFV1-',
    FinalizeDST: 'Finalize',
    HashToGroupDST: 'HashToGroup-',
    HashToScalarDST: 'HashToScalar-',
    DeriveKeyPairDST: 'DeriveKeyPair',
    InfoLabel: 'Info'
} as const
