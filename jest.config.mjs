// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

function getConfig(version) {
    return {
        displayName: version,
        roots: [`./lib/${version}/test`],
        setupFiles: [`./lib/${version}/mockCrypto/mock_crypto.js`]
    }
}

export default {
    moduleFileExtensions: ['js'],
    testEnvironment: 'node',
    transform: {},
    collectCoverage: true,
    verbose: true,
    projects: [getConfig('esm'), getConfig('cjs')]
}
