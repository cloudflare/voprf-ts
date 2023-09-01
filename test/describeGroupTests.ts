import { GroupConsNoble } from '../src/groupNoble.js'
import { GroupConsSjcl } from '../src/groupSjcl.js'
import { GroupCons, Oprf } from '../src/index.js'

const groupConsMatch = process.env.GROUP_CONS

export const testGroups = (
    [
        ['noble', GroupConsNoble],
        ['sjcl', GroupConsSjcl]
    ] as const
).filter(([name]) => {
    return !groupConsMatch || name === groupConsMatch
})

export function describeGroupTests(declare: (group: GroupCons) => void) {
    describe.each(testGroups)(`Group-%s`, (_groupName, groupCons) => {
        Oprf.Group = groupCons
        declare(groupCons)
    })
}
