import * as Base58 from 'base-58'
import sodium from 'libsodium-wrappers'

interface IUnpackedMsg {
    message: string,
    recipientKey: any,
    senderKey: string
    nonRepudiableVerification: boolean
}

interface IJWSUnpacked {
    content: string,
    verkey: string,
    verified: boolean
}

export class DIDComm {

    public readonly ready: Promise<undefined|Error>
    private sodium = sodium

    /**
     * Creates a new PackUnpack object. The returned object contains a .Ready property:
     * a promise that must be resolved before the object can be used. You can
     * simply `await` the resolution of the .Ready property.
     *
     * Example:
     * let packUnpack = new PackUnpack
     * (async () => {
     *  await packUnpack.Ready
     * }())
     */
    constructor() {
        this.ready = new Promise(async (res, rej) => {
            try {
                await sodium.ready
                res(undefined)
            } catch (err) {
                rej(err)
            }
        })
    }

    /**
     * Uses libsodium to generate a key pair, you may pass these keys into the pack/unpack functions
     * @
     */
    public async generateKeyPair(): Promise<sodium.KeyPair> {
        return this.sodium.crypto_sign_keypair()
    }

    /**
     * Used to encrypt or encrypt and sign a message for one or many recipients so the recipients can authenticate the
     * sender in both repudiable and non repudiable formats. By default messages should use repudiable authentication.
     * This should be the most common API used.
     * @param msg the message to be encrypted or encrypted and signed
     * @param recipientKeys the keys which the message will be encrypted for
     * @param senderKeys the keys used to encrypted or encrypt and sign a message
     * @param nonRepudiable determines whether a message is encrypted only or signed and encrypted
     * @returns if nonRepudiable == true returns the msg encrypted and signed as follows JWE(JWS(msg))
     *          if nonRepudiable == false returns the msg encrypted as follows JWE(msg)
     */
    public async pack_auth_msg_for_recipients(
        msg: string, recipientKeys: Uint8Array[],
        senderKeys: sodium.KeyPair,
        nonRepudiable: boolean = false): Promise<string> {
        if (nonRepudiable) {
            // return JWE(JWS(msg))
            const signedMsg = await this.signContent(msg, senderKeys)
            return this.packMessage(signedMsg, recipientKeys, senderKeys)
        } else {
            // return (JWE(msg))
            return this.packMessage(msg, recipientKeys, senderKeys)

        }
    }

    /**
     *
     * @param msg this is the message which will be anonymously encrypted for one or many recipients
     * @param recipientKeys a list of the recipients keys
     * @returns a JWE with an ephemeral sender key
     */
    public async pack_anon_msg_for_recipients(msg: string, recipientKeys: Uint8Array[]): Promise<string> {
        return this.packMessage(msg, recipientKeys, null)
    }

    /**
     *
     * @param msg the message to signed with non-repudiation but not encrypted
     * @param senderKeys the key used to sign the
     * @returns a compact JWS
     */
    public async pack_nonrepudiable_msg_for_anyone(msg: string, senderKeys: sodium.KeyPair): Promise<string> {
        return this.signContent(msg, senderKeys)
    }

    /**
     * Unpacks a message
     * @param encMsg message to be decrypted
     * @param toKeys key pair of party decrypting the message
     */
    public async unpackMessage(packedMsg: string, toKeys: sodium.KeyPair): Promise<IUnpackedMsg> {
        try {
            return await this.unpackEncrypted(packedMsg, toKeys)
        } catch (err) {
            const jwsChecked = this.verifyContent(packedMsg)
            return {
                message: jwsChecked.content,
                nonRepudiableVerification: jwsChecked.verified,
                recipientKey: null,
                senderKey: jwsChecked.verkey,
            }
        }
    }

    public b64url(input: any) {
        return this.sodium.to_base64(input, this.sodium.base64_variants.URLSAFE)
    }

    public b64dec(input: any) {
        return this.sodium.from_base64(input, this.sodium.base64_variants.URLSAFE)
    }

    /**
     *
     * Packs a message.
     * @param message string message to be encrypted
     * @param toKeys public key of the entity encrypting message for
     * @param fromKeys keypair of person encrypting message
     */
    private async packMessage(
        msg: string, recipientKeys: Uint8Array[], fromKeys: sodium.KeyPair | null = null): Promise<string> {

        const [recipsJson, cek] = this.prepareRecipientKeys(recipientKeys, fromKeys)
        const recipsB64 = this.b64url(recipsJson)

        const [ciphertext, tag, iv] = this.encryptPlaintext(msg, recipsB64, cek)

        return JSON.stringify({
            ciphertext: this.b64url(ciphertext),
            iv: this.b64url(iv),
            protected: recipsB64,
            tag: this.b64url(tag),
        })
    }

    private async unpackEncrypted(encMsg: string, toKeys: sodium.KeyPair): Promise<IUnpackedMsg> {
        let wrapper
        if (typeof encMsg === 'string') {
            wrapper = JSON.parse(encMsg)
        } else {
            wrapper = encMsg
        }
        if (typeof toKeys.publicKey === 'string') {
            toKeys.publicKey = Base58.decode(toKeys.publicKey)
        }
        if (typeof toKeys.privateKey === 'string') {
            toKeys.privateKey = Base58.decode(toKeys.privateKey)
        }
        const recipsJson = this.strB64dec(wrapper.protected)
        const recipsOuter = JSON.parse(recipsJson)

        const alg = recipsOuter.alg
        const isAuthcrypt = alg === 'Authcrypt'
        if (!isAuthcrypt && alg !== 'Anoncrypt') {
            throw new Error('Unsupported pack algorithm: ' + alg)
        }
        const [cek, senderVk, recipVk] = this.locateRecKey(recipsOuter.recipients, toKeys)
        if (!senderVk && isAuthcrypt) {
            throw new Error('Sender public key not provided in Authcrypt message')
        }
        const ciphertext = this.b64dec(wrapper.ciphertext)
        const nonce = this.b64dec(wrapper.iv)
        const tag = this.b64dec(wrapper.tag)

        const message = this.decryptPlaintext(ciphertext, tag, wrapper.protected, nonce, cek)
        try {
            const jwsVerified = this.verifyContent(message)
            return {
                message: jwsVerified.content,
                nonRepudiableVerification: senderVk === jwsVerified.verkey ? true : false,
                recipientKey: recipVk,
                senderKey: senderVk,
            }
        } catch (err) {
            return {
                message,
                nonRepudiableVerification: false,
                recipientKey: recipVk,
                senderKey: senderVk,
            }
        }
    }

    private async signContent(msg: string, signerKeyPair: sodium.KeyPair): Promise<string> {
        // get public key base58 encoded
        const senderVk = Base58.encode(signerKeyPair.publicKey)

        // generate jose header, b64url encode it, and concat to b64url encoded payload
        const joseHeader = {
            alg: 'EdDSA',
            kid: senderVk,
        }
        const joseString = JSON.stringify(joseHeader)
        const b64JoseStr = this.b64url(joseString)
        const b64Payload = this.b64url(msg)
        const headerAndPayloadConcat = `${b64JoseStr}.${b64Payload}`

        // sign data and return compact JWS
        const signature = this.b64url(sodium.crypto_sign(headerAndPayloadConcat, signerKeyPair.privateKey))
        return `${headerAndPayloadConcat}.${signature}`
    }

    private verifyContent(jws: string): IJWSUnpacked {
        const jwsSplit = jws.split('.')
        const joseHeader = JSON.parse(this.strB64dec(jwsSplit[0]))
        if (joseHeader.alg !== 'EdDSA') {
            throw new Error('Cryptographic algorithm unidentifiable')
        }
        const sigMsg = sodium.crypto_sign_open(this.b64dec(jwsSplit[2]), Base58.decode(joseHeader.kid))

        return {
            content: this.strB64dec(jwsSplit[1]),
            verified: (sodium.to_string(sigMsg) === `${jwsSplit[0]}.${jwsSplit[1]}`) ? true : false,
            verkey: joseHeader.kid,
        }
    }

    private strB64dec(input: any) {
        return this.sodium.to_string(this.sodium.from_base64(input, this.sodium.base64_variants.URLSAFE))
    }

    private encryptPlaintext(message: any, addData: any, key: any) {
        const iv = this.sodium.randombytes_buf(this.sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
        const out = this.sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(message, addData, null, iv, key)
        return [out.ciphertext, out.mac, iv]
    }

    private decryptPlaintext(ciphertext: any, mac: any, recipsBin: any, nonce: any, key: any) {
        return this.sodium.to_string(
            this.sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(
                null, // nsec
                ciphertext,
                mac,
                recipsBin, // ad
                nonce, // npub
                key,
            ),
        )
    }

    private prepareRecipientKeys(toKeys: any, fromKeys: any = null) {
        const cek = this.sodium.crypto_aead_chacha20poly1305_ietf_keygen()
        const recips: any[] = []

        toKeys.forEach((targetVk: any) => {
            let encCek = null
            let encSender = null
            let nonce = null

            const targetPk = this.sodium.crypto_sign_ed25519_pk_to_curve25519(targetVk)

            if (fromKeys) {
                const senderVk = Base58.encode(fromKeys.publicKey)
                const senderSk = this.sodium.crypto_sign_ed25519_sk_to_curve25519(fromKeys.privateKey)
                encSender = this.sodium.crypto_box_seal(senderVk, targetPk)

                nonce = this.sodium.randombytes_buf(this.sodium.crypto_box_NONCEBYTES)
                encCek = this.sodium.crypto_box_easy(cek, nonce, targetPk, senderSk)
            } else {
                encCek = this.sodium.crypto_box_seal(cek, targetPk)
            }

            recips.push(
                {
                    encrypted_key: this.b64url(encCek),
                    header: {
                        iv: nonce ? this.b64url(nonce) : null,
                        kid: Base58.encode(targetVk),
                        sender: encSender ? this.b64url(encSender) : null,
                    },
                },
            )
        })

        const data = {
            alg: fromKeys ? 'Authcrypt' : 'Anoncrypt',
            enc: 'chacha20poly1305_ietf',
            recipients: recips,
            typ: 'JWM/1.0',
        }
        return [JSON.stringify(data), cek]
    }

    private locateRecKey(recipients: any, keys: any) {
        const notFound = []
        /* tslint:disable */
        for (let index in recipients) {
            let recip = recipients[index]
            if (!('header' in recip) || !('encrypted_key' in recip)) {
                throw new Error('Invalid recipient header')
            }

            let recipVk = Base58.decode(recip.header.kid)
            if (!this.sodium.memcmp(recipVk, keys.publicKey)) {
                notFound.push(recip.header.kid)
            }
            let pk = this.sodium.crypto_sign_ed25519_pk_to_curve25519(keys.publicKey)
            let sk = this.sodium.crypto_sign_ed25519_sk_to_curve25519(keys.privateKey)

            let encrytpedKey = this.b64dec(recip.encrypted_key)
            let nonce = recip.header.iv ? this.b64dec(recip.header.iv) : null
            let encSender = recip.header.sender ? this.b64dec(recip.header.sender) : null

            let senderVk = null
            let cek = null
            if (nonce && encSender) {
                senderVk = this.sodium.to_string(this.sodium.crypto_box_seal_open(encSender, pk, sk))
                let senderPk = this.sodium.crypto_sign_ed25519_pk_to_curve25519(Base58.decode(senderVk))
                cek = this.sodium.crypto_box_open_easy(encrytpedKey, nonce, senderPk, sk)
            } else {
                cek = this.sodium.crypto_box_seal_open(encrytpedKey, pk, sk)
            }
            return [cek, senderVk, recip.header.kid]
        }

        throw new Error('No corresponding recipient key found in recipients')
    }
}
