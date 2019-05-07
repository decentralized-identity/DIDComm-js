import _sodium = require('libsodium-wrappers')
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

    it('it packs and unpacks a DIDComms message', async () => {
        // Prep test suite
        const packUnpack = new PackUnpack()
        await packUnpack.Ready
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

    it('can use serialized and deserialized keys', async () => {
        // Prep test suite
        const packUnpack = new PackUnpack()
        await packUnpack.Ready
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

        interface IJSONKeyPair {
            keyType: string,
            privateKey: number[],
            publicKey: number[],
        }
        const msg: IJSONKeyPair = {
            keyType: alice.keyType,
            privateKey: Array.from(alice.privateKey),
            publicKey: Array.from(alice.publicKey),
        }

        const JM = JSON.stringify(msg)
        const UJM = JSON.parse(JM)

        const keys: _sodium.KeyPair  = {
            keyType: UJM.keyType,
            privateKey: Uint8Array.from(UJM.privateKey),
            publicKey: Uint8Array.from(UJM.publicKey),
        }

        const packedMsg = await packUnpack.packMessage(message, [bob.publicKey], keys)
        const unpackedMsg = await packUnpack.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
    })
})
