import { DIDComm } from './index'
import sodium from 'libsodium-wrappers'

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
            publicKey: didcomm.b64dec('huhCS7nknreumNZyDM5x565PQmt7QGuaoqzVlqyYHJ8='),
            privateKey: didcomm.b64dec('4hUOfejoCMv2Pjy1z_MzftFYgCwINh3rgwoRK_iFu1KG6EJLueSet66Y1nIMznHnrk9Ca3tAa5qirNWWrJgcnw=='),
            keyType: 'ed25519'
        }
        const message = 'I AM A PRIVATE MESSAGE'
        const packedMsg = '{"ciphertext": "nG5VtCGpojKCjjegyi03O4SieBtN6w==","iv": "CG_v-eia5tYKJAdo", "protected": "eyJhbGciOiJBdXRoY3J5cHQiLCJlbmMiOiJjaGFjaGEyMHBvbHkxMzA1X2lldGYiLCJyZWNpcGllbnRzIjpbeyJlbmNyeXB0ZWRfa2V5IjoiMDFrWTQ1cEVYYUhMdU10ZTlhRTZtYUhtMDFRMU5Sam5MQUVpU3FoNmhZS2FvUWMyZEgwbzRsMzZEOXFzbGFoaiIsImhlYWRlciI6eyJpdiI6IlNDY095WGV2b0hXVXA2ZXFWZmJnamZuR3lNS0RoMGszIiwia2lkIjoiQTVkM1R6eGJwbUxBNTRNU2E4MmppUFhqM1JUeHN0dTZxZjdzc0x4UXlBQTIiLCJzZW5kZXIiOiI1NG5FLTF0YmpZdUZKa1BCWGNtbjdZUXN3Q19jREdmQlIyOXV4Q1RKdVZXbWJZX2UyYk0zNE9HbFBQWGN6aHFRZzIySWwwWVB5MW9uRGR0ei0tMHNNN2dKS1FfMkZMRlJFcW05cmZkOFIwWTdxUnVCTWJxOHR5cmdjOWs9In19XSwidHlwIjoiSldNLzEuMCJ9","tag": "ZESRpQjSJ6J9zljNS_a3iw=="}'
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
            publicKey: didcomm.b64dec('huhCS7nknreumNZyDM5x565PQmt7QGuaoqzVlqyYHJ8='),
            privateKey: didcomm.b64dec('4hUOfejoCMv2Pjy1z_MzftFYgCwINh3rgwoRK_iFu1KG6EJLueSet66Y1nIMznHnrk9Ca3tAa5qirNWWrJgcnw=='),
            keyType: 'ed25519'
        }
        const message = 'I AM A PRIVATE MESSAGE'

        const packedMsg = '{"ciphertext":"6aP_ua5UKa56F5OyDTxc-RXl0o03xI7fjGhD8coVWMvo7846IoW7P2Ulj07uFNLhaOs2GA3vrpA9eyFIVGMATm1vGndge7FZcM-rpuvRT4EywQGT91VYrNRqxkr_MU8eqAMJjsa6gimmMop-VAlXkNLYH7pnSErSK3cYQNLVEwjEzY6rkBnWQEmoy0CUWlweNqeuNl8bi5hqSdKTvs2BrG2EC3eWuti8yZRdEto4xU62AVtF_aVd_6OjebfASWHKP_uWXeDPl4yXcf8SNlUdROpQGBoK1mVKtREkKCImI53yxQxhOIhHxpCeKIi8IH4jx0AyEa--_2Cnj2g5rinVQiZicNypyBQCZMTsXwjsSMOFO0K8c5lzCZrMno-W9AktyVI81Up6AMaXkM3NpFqKQhTM4eOw4W-NoOzOybMTba3qfgbb0GQ-muUQbUNjcnf_T8vMbZNjb2LlWVaK0zQ_ZOo9lrr0EuQUdWBxZr4j81qslfq-lZyw6YTR","iv":"Jhazdl_wAFhFePuI","protected":"eyJhbGciOiJBdXRoY3J5cHQiLCJlbmMiOiJjaGFjaGEyMHBvbHkxMzA1X2lldGYiLCJyZWNpcGllbnRzIjpbeyJlbmNyeXB0ZWRfa2V5IjoidDRWeUwzd0VhQ0NwOUhyZ1JIWHVhVzgtUk41ZFA5ZlJJOWd2UUxURkpYeUJOZlNTS2lPY2VTRnBqd1l6QmlxdiIsImhlYWRlciI6eyJpdiI6Ik9qcDVmWnNsY2pLQ0xjUGUyRk9QUnBCRnU1YVhRTUhUIiwia2lkIjoiQTVkM1R6eGJwbUxBNTRNU2E4MmppUFhqM1JUeHN0dTZxZjdzc0x4UXlBQTIiLCJzZW5kZXIiOiJCSWZzaDVHNE1FRnN4ZTMtN3BaSm9BMHptLTdTb1FSZVVLY2xLdjBPTlRDZ0J4dVQ1aG9lS0dRWEEwMS01YWROWHhEZGNJU2tvcXFONjZzd2JiaGRRYmxVLUFKd2NST3I4NXRweC10T1lmZzB2bVNuTkg4Rm5DdC1UcGs9In19XSwidHlwIjoiSldNLzEuMCJ9","tag":"Lq2CYyWqpzcdCtpS5C1Hvw=="}'
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
        await didcomm.ready
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
        await didcomm.ready
        const bob = await didcomm.generateKeyPair()
        const message = "I AM A PUBLIC MESSAGE"

        const packedMsg = await didcomm.pack_nonrepudiable_msg_for_anyone(message, bob)
        const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
        expect(unpackedMsg.message).toEqual(message)
        expect(unpackedMsg.recipientKey).toEqual(null)
    })
})
