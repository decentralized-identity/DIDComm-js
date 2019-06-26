import { PackUnpack } from '.'

describe('pack and unpack', () => {

    it('is an async constructor', async () => {
        const packUnpack = new PackUnpack()
        const unresolvedVal = packUnpack.Ready
        expect(unresolvedVal).toBeInstanceOf(Promise)
        const val = await packUnpack.Ready
        expect(val).toEqual(undefined)
    })

    it('it packs and unpacks a message', async () => {
        // Prep test suite
        const packUnpack = new PackUnpack()
        await packUnpack.Ready
        const alice = await packUnpack.generateKeyPair()
        const bob = await packUnpack.generateKeyPair()
        const message = 'I AM A PRIVATE MESSAGE'

        const packedMsg = await packUnpack.packMessage(message, [bob.publicKey], alice)
        const unpackedMsg = await packUnpack.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
    })
})
