import { PackUnpack } from '.'

describe('pack and unpack', () => {

    it('it packs and unpacks a message', async () => {
        // Prep test suite
        const packUnpack = new PackUnpack()
        await packUnpack.setup()
        const alice = await packUnpack.generateKeyPair()
        const bob = await packUnpack.generateKeyPair()
        const message = 'I AM A PRIVATE MESSAGE'

        const packedMsg = await packUnpack.packMessage(message, [bob.publicKey], alice)
        const unpackedMsg = await packUnpack.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
    })

    it('it packs and unpacks a DIDComms message', async () => {
        // Prep test suite
        const packUnpack = new PackUnpack()
        await packUnpack.setup()
        const alice = await packUnpack.generateKeyPair()
        const bob = await packUnpack.generateKeyPair()
        const message = JSON.stringify({
            '@id': '1111-22222-3333-44444',
            '@type': 'DID:sov;spec/enroll/0.1/status',
            'message': 'Invite has been sent to the user',
            'status': 5,
            '~thread': {
                thid: 'prev_thread_1234',
            },
        })

        const packedMsg = await packUnpack.packMessage(message, [bob.publicKey], alice)
        const unpackedMsg = await packUnpack.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
    })
})
