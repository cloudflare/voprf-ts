import type { Client, FinalizeData as FacadeFinalizeData } from '../types.js'
import { OPRFClient, VOPRFClient, POPRFClient } from '../../client.js'
import { MODE } from '../../consts.js'
import { OprfBaseImpl } from './OprfBaseImpl.js'
import { FinalizeData, EvaluationRequest } from '../../oprf.js'

export class ClientImpl extends OprfBaseImpl implements Client {
    spyHandle: Client['spyHandle']
    blind: Client['blind']
    finalize: Client['finalize']

    constructor(
        publicKey: Uint8Array | undefined,
        ...args: ConstructorParameters<typeof OprfBaseImpl>
    ) {
        super(...args)
        let wrapped: OPRFClient | VOPRFClient | POPRFClient
        switch (this.mode) {
            case MODE.OPRF:
                wrapped = new OPRFClient(this.suite, this.crypto)
                break
            case MODE.POPRF:
                if (!publicKey) {
                    throw new Error(`public key must be set for the POPRF mode`)
                }
                wrapped = new POPRFClient(this.suite, publicKey, this.crypto)
                break
            case MODE.VOPRF:
                if (!publicKey) {
                    throw new Error(`public key must be set for the VOPRF mode`)
                }
                wrapped = new VOPRFClient(this.suite, publicKey, this.crypto)
                break
            default:
                throw new Error(`Unsupported mode: ${this.mode}`)
        }
        this.blind = async (inputs: Uint8Array[]) => {
            const [finData, evalReq] = await wrapped.blind(inputs)
            return [finData, this.codec.encodeEvaluationRequest(evalReq)]
        }
        this.finalize = (finData, evaluation, info) => {
            return wrapped.finalize(
                this.mapFinalizationData(finData),
                this.codec.decodeEvaluation({ mode: this.mode, ...evaluation }),
                info as Uint8Array<ArrayBuffer>
            )
        }
        this.spyHandle = { blinds: wrapped }
    }

    private mapFinalizationData(fac: FacadeFinalizeData): FinalizeData {
        if (fac instanceof FinalizeData) {
            return fac
        }
        return new FinalizeData(fac.inputs, fac.blinds, new EvaluationRequest(fac.evalReq.blinded))
    }
}
