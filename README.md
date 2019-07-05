# DIDComm-crypto-js
Javascript (written in typescript) version of the cryptographic envelope of DIDComm. This library is built for any javascript environment that needs to . It is built on libsodium-js and follows the specs documented in the [docs](/docs/README.md) folder.

## installation
This package is currently not available on NPM: It will be added to npm under the package name `DIDComm-crypto-js` when a CI/CD platform can be added to publish it.

## Usage

**NOTE THESE APIs are currently unstable at this point to account for new non-repudiable signing changes**

There's currently 4 APIs of use in this library that will handle encryption and decryption to multiple recipients. Messages encrypted with this library support repudiable authentication and anonymous encryption. There's additional APIs to support non-repudiable signing and verification of messages.

### Encrypt with repudiable authentication
pack_auth_msg_for_recipients(message, recipientKeyList, senderKeyPair, nonRepudiable = false) should be the default method used. This example shows how to use repudiable authentication to pack a message for the recipient.

```typescript
    const didcomm = new DIDComm()
    await didcomm.Ready
    const alice = await didcomm.generateKeyPair()
    const bob = await didcomm.generateKeyPair()
    const message = 'I AM A PRIVATE MESSAGE'
    const packedMsg = await didcomm.pack_auth_msg_for_recipients(message, [bob.publicKey], alice)
    const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
```

### Encrypt with non-repudiable authentication
To Encrypt a message for a recipient and sign the message using a non-repudiable signature change the nonRepudiable variable should be set to `true`. To understand what non-repudiation is and when it should be used refer here.

```typescript
    const didcomm = new DIDComm()
    await didcomm.Ready
    const alice = await didcomm.generateKeyPair()
    const bob = await didcomm.generateKeyPair()
    const message = 'I AM A PRIVATE MESSAGE'
    const packedMsg = await didcomm.pack_auth_msg_for_recipients(message, [bob.publicKey], alice, true)
    const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
```

### Encrypt with no authentication

For privacy reasons or to meet the principle of least information, it may be necessary to encrypt a message, but does  not provide authentication guarantees. 

```typescript
    const didcomm = new DIDComm()
    await didcomm.Ready
    const bob = await didcomm.generateKeyPair()
    const message = JSON.stringify({
        "@type": "did:example:1234567890;spec/test",
        data: "I AM A SIGNED MESSAGE"
    })
    const packedMsg = await didcomm.pack_anon_msg_for_recipients(message, [bob.publicKey])
    const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
```

### Non-repudiable signature with no encryption

In very specific use cases like the invitation protocol or incredibly short lived connection (1 round trip only) it's necessary to provide data in a plaintext format to provide a key. In these cases we will sign the data, but leave it unencrypted.

```typescript
    const didcomm = new DIDComm()
    await didcomm.Ready
    const bob = await didcomm.generateKeyPair()
    const message = "I AM A PUBLIC MESSAGE"
    const packedMsg = await didcomm.pack_nonrepudiable_msg_for_anyone(message, bob)
    const unpackedMsg = await didcomm.unpackMessage(packedMsg, bob)
```

## Authentication notes

To perform authentication this library should be combined with resolution of a DID Document to ensure the key used by the sender is contained in a valid DID Document. This funcationality is considered out of scope for this library. 