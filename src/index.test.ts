import { DIDComm } from '.'

describe('pack and unpack', () => {

    it('it packs and unpacks a message with repudiable authentication', async () => {
        // Prep test suite
        const didcomm = new DIDComm()
        const alice = await didcomm.generateKeyPair()
        const bob = await didcomm.generateKeyPair()
        const message = 'I AM A PRIVATE MESSAGE'

        const packedMsg = await didcomm.pack_auth_msg_for_recipients(message, [bob.publicKey], alice)
        const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
    })

    it('it packs and unpacks a message with nonrepudiable authentication', async () => {
        // Prep test suite
        const didcomm = new DIDComm()
        const alice = await didcomm.generateKeyPair()
        const bob = await didcomm.generateKeyPair()
        const message = 'I AM A PRIVATE MESSAGE'

        const packedMsg = await didcomm.pack_auth_msg_for_recipients(message, [bob.publicKey], alice, true)
        const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
        expect(unpackedMsg.nonRepudiableVerification).toEqual(true)
    })

    it('it checks that a packed message with alg still gets unpacked properly', async () => {
        // Prep test suite
        const didcomm = new DIDComm()
        const alice = await didcomm.generateKeyPair()
        const bob = await didcomm.generateKeyPair()
        const message = JSON.stringify({
            "@type": "did:example:1234567890;spec/test",
            alg: "edDSA",
            data: "I AM A SIGNED MESSAGE"
        })

        const packedMsg = await didcomm.pack_auth_msg_for_recipients(message, [bob.publicKey], alice)
        const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
    })

    it('it checks that an anonymous packed message can be unpacked', async () => {
        // Prep test suite
        const didcomm = new DIDComm()
        const bob = await didcomm.generateKeyPair()
        const message = JSON.stringify({
            "@type": "did:example:1234567890;spec/test",
            alg: "edDSA",
            data: "I AM A SIGNED MESSAGE"
        })

        const packedMsg = await didcomm.pack_anon_msg_for_recipients(message, [bob.publicKey])
        const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
    })

    it('it checks that an anonymous packed message can be unpacked', async () => {
        // Prep test suite
        const didcomm = new DIDComm()
        const bob = await didcomm.generateKeyPair()
        const message = "I AM A PUBLIC MESSAGE"

        const packedMsg = await didcomm.pack_nonrepudiable_msg_for_anyone(message, bob)
        const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
        expect(unpackedMsg.recipientKey).toEqual(null)
    })
})
