import sodium = require('libsodium-wrappers')
import { PackUnpack } from '.'

describe('pack and unpack', () => {

    test('it packs and unpacks a message', async () => {
        // Prep test suite
        const packUnpack = new PackUnpack()
        await packUnpack.setup()
        const alice = sodium.crypto_sign_keypair()
        const bob = sodium.crypto_sign_keypair()

        const message = 'I AM A PRIVATE MESSAGE'
        const packedMsg = await packUnpack.packMessage(message, [bob.publicKey], alice)
        const unpackedMsg = await packUnpack.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
    })
})