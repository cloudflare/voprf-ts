import type { Server } from '../types.js'
import { OPRFServer, VOPRFServer, POPRFServer } from '../../server.js'
import { MODE } from '../../consts.js'
import { OprfBaseImpl } from './OprfBaseImpl.js'

export class ServerImpl extends OprfBaseImpl implements Server {
    verifyFinalize: Server['verifyFinalize']
    blindEvaluate: Server['blindEvaluate']
    spyHandle: Server['spyHandle']

    constructor(privateKey: Uint8Array, ...args: ConstructorParameters<typeof OprfBaseImpl>) {
        super(...args)
        let wrapped: OPRFServer | VOPRFServer | POPRFServer
        switch (this.mode) {
            case MODE.OPRF:
                wrapped = new OPRFServer(this.suite, privateKey, this.crypto)
                break
            case MODE.POPRF:
                wrapped = new POPRFServer(this.suite, privateKey, this.crypto)
                break
            case MODE.VOPRF:
                wrapped = new VOPRFServer(this.suite, privateKey, this.crypto)
                break
            default:
                throw new Error(`Unsupported mode: ${this.mode}`)
        }
        this.spyHandle = {
            dleqProver: wrapped['prover']
        }
        this.verifyFinalize = wrapped.verifyFinalize.bind(wrapped)
        this.blindEvaluate = async (req, ...info) => {
            const internal = await wrapped.blindEvaluate(
                this.codec.decodeEvaluationRequest(req),
                ...info
            )
            return this.codec.encodeEvaluation(internal)
        }
    }
}
