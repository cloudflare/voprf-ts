// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

function getConfig(version) {
    return {
        displayName: version,
        roots: [`./lib/${version}/test`],
        moduleFileExtensions: ['js'],
        testEnvironment: 'node',
        transform: {},
        setupFiles: [`./lib/${version}/test/jest.setup.js`],
        collectCoverage: true,
        coverageDirectory: `coverage/${version}`,
        verbose: true
    }
}

export default {
    projects: [getConfig('esm'), getConfig('cjs')]
}
