import _sodium = require('libsodium-wrappers')
import { PackUnpack } from '.'

describe('pack and unpack', () => {

    it('it packs and unpacks a message', async () => {
        // Prep test suite
        const packUnpack = new PackUnpack()
        await packUnpack.setup()
        await _sodium.ready
        const sodium = _sodium
        const alice = sodium.crypto_sign_keypair()
        const bob = sodium.crypto_sign_keypair()
        const message = 'I AM A PRIVATE MESSAGE'

        const packedMsg = await packUnpack.packMessage(message, [bob.publicKey], alice)
        const unpackedMsg = await packUnpack.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
    })

    it('it packs and unpacks a DIDComms message', async () => {
        // Prep test suite
        const packUnpack = new PackUnpack()
        await packUnpack.setup()
        await _sodium.ready
        const sodium = _sodium
        const alice = sodium.crypto_sign_keypair()
        const bob = sodium.crypto_sign_keypair()
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
