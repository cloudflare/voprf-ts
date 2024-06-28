import globals from 'globals'
import tsParser from '@typescript-eslint/parser'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import js from '@eslint/js'
import { FlatCompat } from '@eslint/eslintrc'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const compat = new FlatCompat({
    baseDirectory: __dirname,
    recommendedConfig: js.configs.recommended,
    allConfig: js.configs.all
})

export default [
    {
        ignores: ['coverage/*', 'src/sjcl/index.js', 'src/sjcl/index.d.ts', 'lib/*']
    },
    ...compat.extends(
        'eslint:recommended',
        'plugin:security/recommended-legacy',
        'plugin:prettier/recommended'
    ),
    {
        languageOptions: {
            globals: {
                ...globals.browser,
                ...globals.node
            },

            ecmaVersion: 2020,
            sourceType: 'module',

            parserOptions: {
                project: true
            }
        }
    },
    ...compat
        .extends(
            'plugin:@typescript-eslint/eslint-recommended',
            'plugin:@typescript-eslint/recommended',
            'plugin:jest-formatting/recommended',
            'plugin:jest/recommended',
            'prettier'
        )
        .map((config) => ({
            ...config,
            files: ['**/*.ts']
        })),
    {
        files: ['**/*.ts'],

        languageOptions: {
            parser: tsParser,
            ecmaVersion: 2020,
            sourceType: 'module'
        },

        rules: {
            'max-lines-per-function': [
                'warn',
                {
                    max: 100,
                    skipComments: true,
                    skipBlankLines: true
                }
            ],

            'max-statements': ['warn', 50],
            'max-params': ['warn', 5],
            'no-loop-func': 'warn',
            'max-lines': 'off',
            'no-ternary': 'off',
            'no-inline-comments': 'off',
            'line-comment-position': 'off',
            'no-magic-numbers': 'off',
            'id-length': 'off',
            'max-classes-per-file': 'off',
            'sort-keys': 'off',
            'sort-vars': 'off',
            'no-bitwise': 'off',
            'no-plusplus': 'off',
            'capitalized-comments': 'off',
            'multiline-comment-style': 'off',
            'func-style': ['error', 'declaration'],
            'one-var': ['error', 'never'],
            '@typescript-eslint/no-namespace': 'warn',

            '@typescript-eslint/no-unused-vars': [
                'error',
                {
                    argsIgnorePattern: '^_'
                }
            ],

            '@typescript-eslint/consistent-type-imports': 'error',
            '@typescript-eslint/consistent-type-exports': 'error'
        }
    }
]
