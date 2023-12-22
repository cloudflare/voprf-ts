import type { ModeID, SuiteID } from '../types.js'
import { Codec } from './Codec.js'
import type { CryptoProvider } from '../../cryptoTypes.js'
import type { Group } from '../../groupTypes.js'

export class OprfBaseImpl {
    protected codec = new Codec(this.group, this.crypto)

    constructor(
        public mode: ModeID,
        public suite: SuiteID,
        public crypto: CryptoProvider,
        public group: Group
    ) {}
}
