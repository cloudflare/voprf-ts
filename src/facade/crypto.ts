import { CryptoImpl } from '../cryptoImpl.js'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Func = (...args: any[]) => any

export type FuncKeys<T> = {
    [K in keyof T]: T[K] extends Func ? (K extends string ? K : never) : never
}[keyof T]

export type AllFuncKeys<T> = Readonly<
    {
        [K in FuncKeys<T>]: Readonly<K>
    }[FuncKeys<T>][]
>

export const MODE_FUNCS = [
    'getKeySizes',
    'validatePrivateKey',
    'validatePublicKey',
    'randomPrivateKey',
    'derivePrivateKey',
    'generatePublicKey',
    'generateKeyPair',
    'deriveKeyPair'
] as const

export const CLIENT_FUNCS = ['blind', 'finalize'] as const

export const SERVER_FUNCS = [
    'blindEvaluate',
    'constructDLEQParams',
    'evaluate',
    'verifyFinalize'
] as const

export function errorIfCryptoChanged<T>(bind: string, val: T, keys: AllFuncKeys<T>) {
    const toWrap = val as Record<string, Func>
    keys.forEach((key) => {
        const original = toWrap[`${key}`].bind(val)
        toWrap[`${key}`] = (...args: unknown[]) => {
            if (bind !== CryptoImpl.name) {
                throw new Error('Currently only one supported CryptoProvider at a time')
            }
            return original(...args)
        }
    })
    Object.keys(toWrap).forEach((k) => {
        if (
            typeof toWrap[`${k}`] === 'function' &&
            !keys.includes(k as unknown as (typeof keys)[number])
        ) {
            throw new Error(`unspecified function ${k} not in ${keys}`)
        }
    })
    return val
}
