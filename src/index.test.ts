import sodium from 'libsodium-wrappers'
import { DIDComm } from './index'

describe('pack and unpack', () => {

    it('is an async constructor', async () => {
        const didcomm = new DIDComm()
        const unresolvedVal = didcomm.ready
        expect(unresolvedVal).toBeInstanceOf(Promise)
        const val = await didcomm.ready
        expect(val).toEqual(undefined)
    })

    it('it packs and unpacks a message with repudiable authentication', async () => {
        // Prep test suite
        const didcomm = new DIDComm()
        await didcomm.ready
        const alice = await didcomm.generateKeyPair()
        const bob = await didcomm.generateKeyPair()
        const message = 'I AM A PRIVATE MESSAGE'

        const packedMsg = await didcomm.pack_auth_msg_for_recipients(message, [bob.publicKey], alice)
        const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
    })

    it('it unpacks an existing message with repudiable authentication', async () => {
        // Prep test suite
        const didcomm = new DIDComm()
        await didcomm.ready
        const bob: sodium.KeyPair = {
            keyType: 'ed25519',
            privateKey: didcomm.b64dec('oQpOmUOpCce9pnJb13I-RYG1m_1VLm3tvJq3R2P7KhAikr9DGrKkry5ppd0TOPuqPl7tADB2JwChZ8L_KKnbEw'),
            publicKey: didcomm.b64dec('IpK_QxqypK8uaaXdEzj7qj5e7QAwdicAoWfC_yip2xM'),
        }
        const message = 'I AM A PRIVATE MESSAGE'
        const packedMsg = '{"ciphertext":"IM-OK82xvazYlHMPw8bjvlMd-0iLBUi3silUnFTDmARv90oUp8tySou_PmQEpjK4rTAeAfvta6kSPTC_M3ORnqhmanioCNYrkFxTNLVUv7GLrSj8kQ0ENudxxIMPfMEUoUAgQm4EdeESBIM1UoP6V5ys3KdA5sH1P3HCp7wlS29MNRgNKla2vx6rC3JreLI40qj7L0LTjnnzq1_RNjEvWJyfRx6a6DWGiJ5GY9WExozOGmRi-5gc1hItQKGypvCCGOR3NLEr1KUHn5Vr0CxJ3V3C1momtJSYpjPxNLgXH-1E7yaNTDnCBZ0Oecr9LS5j-HxQB4aDcrYQ3UHY2C5KaJQYpPLgbtrYNHUuRH_7RqzTq3CMAPkak5_ZvNplOOjFFxorzC_ZwNMP64njhpk-a6CV1hN4jbeFwI96RU93jMbFqY96Flmj_d4cih-ptL9ub4DUOiQ5qX7bczJZjaNhPadqPeKFG3Kin36BPihjzfkaBTw","iv":"3NZtBtHQ8cLS6a1v","protected":"eyJhbGciOiJBdXRoY3J5cHQiLCJlbmMiOiJjaGFjaGEyMHBvbHkxMzA1X2lldGYiLCJyZWNpcGllbnRzIjpbeyJlbmNyeXB0ZWRfa2V5IjoicVpWU3BmTHlnQWMybzlfZVpKTmZVWnI4UTE2Ty02NzVJbE5KYXR1MXJQVWFJeE1Xa2gwbXJhWklCcGF5UW1aNCIsImhlYWRlciI6eyJpdiI6IlFEWkM0Y1R5UGh3cHozeFl3QTAwcDVpcFRxU19qZnFPIiwia2lkIjoiM0t4ZVNyeEFMM05Ga0ZXenlXb2hvemtlUTZjZGVDRmJOZkFBQk44bWN6UTIiLCJzZW5kZXIiOiJnbmJNV3RDYnFMblRHNGZNdllxRmJKeV9wRUxyYlZUSjBla0EyWmVLbGstR2lEQnp4Sjc1X240bUtteXpDQ1NfTTIxM1gyRzN3RnFEbTVSRVJaakdTbmFlMl9tYk1sRHN4X1V2cjBLX2FISHpUM0FHU2Y5XzNVbFZOUFkifX1dLCJ0eXAiOiJKV00vMS4wIn0","tag":"tfkymuUHGyEl-2IuVnG3AQ"}'
        const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
    })

    it('it packs and unpacks a message with nonrepudiable authentication', async () => {
        // Prep test suite
        const didcomm = new DIDComm()
        await didcomm.ready
        const alice = await didcomm.generateKeyPair()
        const bob = await didcomm.generateKeyPair()
        const message = 'I AM A PRIVATE MESSAGE'

        const packedMsg = await didcomm.pack_auth_msg_for_recipients(message, [bob.publicKey], alice, true)
        const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
        expect(unpackedMsg.nonRepudiableVerification).toEqual(true)
    })

    it('it unpacks an existing message with nonrepudiable authentication', async () => {
        // Prep test suite
        const didcomm = new DIDComm()
        await didcomm.ready
        const bob: sodium.KeyPair = {
            keyType: 'ed25519',
            privateKey: didcomm.b64dec('oQpOmUOpCce9pnJb13I-RYG1m_1VLm3tvJq3R2P7KhAikr9DGrKkry5ppd0TOPuqPl7tADB2JwChZ8L_KKnbEw'),
            publicKey: didcomm.b64dec('IpK_QxqypK8uaaXdEzj7qj5e7QAwdicAoWfC_yip2xM'),
        }
        const message = 'I AM A PRIVATE MESSAGE'

        const packedMsg = '{"ciphertext":"IM-OK82xvazYlHMPw8bjvlMd-0iLBUi3silUnFTDmARv90oUp8tySou_PmQEpjK4rTAeAfvta6kSPTC_M3ORnqhmanioCNYrkFxTNLVUv7GLrSj8kQ0ENudxxIMPfMEUoUAgQm4EdeESBIM1UoP6V5ys3KdA5sH1P3HCp7wlS29MNRgNKla2vx6rC3JreLI40qj7L0LTjnnzq1_RNjEvWJyfRx6a6DWGiJ5GY9WExozOGmRi-5gc1hItQKGypvCCGOR3NLEr1KUHn5Vr0CxJ3V3C1momtJSYpjPxNLgXH-1E7yaNTDnCBZ0Oecr9LS5j-HxQB4aDcrYQ3UHY2C5KaJQYpPLgbtrYNHUuRH_7RqzTq3CMAPkak5_ZvNplOOjFFxorzC_ZwNMP64njhpk-a6CV1hN4jbeFwI96RU93jMbFqY96Flmj_d4cih-ptL9ub4DUOiQ5qX7bczJZjaNhPadqPeKFG3Kin36BPihjzfkaBTw","iv":"3NZtBtHQ8cLS6a1v","protected":"eyJhbGciOiJBdXRoY3J5cHQiLCJlbmMiOiJjaGFjaGEyMHBvbHkxMzA1X2lldGYiLCJyZWNpcGllbnRzIjpbeyJlbmNyeXB0ZWRfa2V5IjoicVpWU3BmTHlnQWMybzlfZVpKTmZVWnI4UTE2Ty02NzVJbE5KYXR1MXJQVWFJeE1Xa2gwbXJhWklCcGF5UW1aNCIsImhlYWRlciI6eyJpdiI6IlFEWkM0Y1R5UGh3cHozeFl3QTAwcDVpcFRxU19qZnFPIiwia2lkIjoiM0t4ZVNyeEFMM05Ga0ZXenlXb2hvemtlUTZjZGVDRmJOZkFBQk44bWN6UTIiLCJzZW5kZXIiOiJnbmJNV3RDYnFMblRHNGZNdllxRmJKeV9wRUxyYlZUSjBla0EyWmVLbGstR2lEQnp4Sjc1X240bUtteXpDQ1NfTTIxM1gyRzN3RnFEbTVSRVJaakdTbmFlMl9tYk1sRHN4X1V2cjBLX2FISHpUM0FHU2Y5XzNVbFZOUFkifX1dLCJ0eXAiOiJKV00vMS4wIn0","tag":"tfkymuUHGyEl-2IuVnG3AQ"}'
        const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
        expect(unpackedMsg.nonRepudiableVerification).toEqual(true)
    })

    it('it checks that a packed message with alg still gets unpacked properly', async () => {
        // Prep test suite
        const didcomm = new DIDComm()
        await didcomm.ready
        const alice = await didcomm.generateKeyPair()
        const bob = await didcomm.generateKeyPair()
        const message = JSON.stringify({
            '@type': 'did:example:1234567890;spec/test',
            'alg': 'edDSA',
            'data': 'I AM A SIGNED MESSAGE',
        })

        const packedMsg = await didcomm.pack_auth_msg_for_recipients(message, [bob.publicKey], alice)
        const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
    })

    it('it checks that an anonymous packed message can be unpacked', async () => {
        // Prep test suite
        const didcomm = new DIDComm()
        await didcomm.ready
        const bob = await didcomm.generateKeyPair()
        const message = JSON.stringify({
            '@type': 'did:example:1234567890;spec/test',
            'alg': 'edDSA',
            'data': 'I AM A SIGNED MESSAGE',
        })

        const packedMsg = await didcomm.pack_anon_msg_for_recipients(message, [bob.publicKey])
        const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
    })

    it('it checks that an anonymous packed message can be unpacked', async () => {
        // Prep test suite
        const didcomm = new DIDComm()
        await didcomm.ready
        const bob = await didcomm.generateKeyPair()
        const message = 'I AM A PUBLIC MESSAGE'

        const packedMsg = await didcomm.pack_nonrepudiable_msg_for_anyone(message, bob)
        const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
        expect(unpackedMsg.recipientKey).toEqual(null)
    })
})
