import Base58 = require('base-58')
import * as nacl from 'tweetnacl'
import naclutil from 'tweetnacl-util'
import { convertKeyPair, convertPublicKey } from 'ed2curve-esm'
import * as sealedbox from 'tweetnacl-sealedbox-js'

interface IUnpackedMsg {
    message: string,
    recipientKey: any,
    senderKey: string
    nonRepudiableVerification: boolean
}

interface JWSUnpacked {
    content: string,
    verkey: string,
    verified: boolean
}

const JWS_REGEX = /^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/

export class DIDComm {

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
    }

    /**
    * Uses tweetnacl to generate a key pair, you may pass these keys into the pack/unpack functions
    * @
    */
    public async generateKeyPair(): Promise<nacl.SignKeyPair> {
        return nacl.sign.keyPair()
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
        msg: string, recipientKeys: Uint8Array[], senderKeys: nacl.SignKeyPair, nonRepudiable: Boolean = false) : Promise<string> {
        if (nonRepudiable) {
            //return JWE(JWS(msg))
            let signedMsg = await this.signContent(msg, senderKeys);
            return this.packMessage(signedMsg, recipientKeys, senderKeys);
        } else {
            // return (JWE(msg))
            return this.packMessage(msg, recipientKeys, senderKeys);
            
        }
    }

    /**
     * 
     * @param msg this is the message which will be anonymously encrypted for one or many recipients
     * @param recipientKeys a list of the recipients keys
     * @returns a JWE with an ephemeral sender key
     */
    public async pack_anon_msg_for_recipients(msg: string, recipientKeys: Uint8Array[]) : Promise<string> {
        return this.packMessage(msg, recipientKeys, null)
    }


    /**
     * 
     * @param msg the message to signed with non-repudiation but not encrypted
     * @param senderKeys the key used to sign the 
     * @returns a compact JWS
     */
    public async pack_nonrepudiable_msg_for_anyone(msg: string, senderKeys: nacl.SignKeyPair) : Promise<string> {
        return this.signContent(msg, senderKeys);
    }

    /**
     * Unpacks a message
     * @param encMsg message to be decrypted
     * @param toKeys key pair of party decrypting the message
     */
    public async unpackMessage(packedMsg: string, toKeys: nacl.SignKeyPair): Promise<IUnpackedMsg> {
        if (packedMsg.match(JWS_REGEX)) {
            let jws_checked = this.verifyContent(packedMsg)
            return {
                message: jws_checked.content,
                recipientKey: null,
                senderKey: jws_checked.verkey,
                nonRepudiableVerification: jws_checked.verified
            }
        } else {
            return await this.unpackEncrypted(packedMsg, toKeys)
        }
    }

    /**
     *
     * Packs a message.
     * @param message string message to be encrypted
     * @param toKeys public key of the entity encrypting message for
     * @param fromKeys keypair of person encrypting message
     */
    private async packMessage(
        msg: string, recipientKeys: Uint8Array[], fromKeys: nacl.SignKeyPair | null = null): Promise<string> {

        let {data, cek} = this.prepareRecipientKeys(recipientKeys, fromKeys)
        let recipsB64 = this.b64url(data)

        let [ciphertext, iv] = this.encryptPlaintext(naclutil.decodeUTF8(msg), cek)

        return JSON.stringify({
            ciphertext: this.b64url(ciphertext),
            iv: this.b64url(iv),
            protected: recipsB64
        })
    }

    private async unpackEncrypted(encMsg: string, toKeys: nacl.SignKeyPair): Promise<IUnpackedMsg> {
        let wrapper
        if (typeof encMsg === 'string') {
            wrapper = JSON.parse(encMsg)
        } else {
            wrapper = encMsg
        }
        let recipsJson = this.strB64dec(wrapper.protected)
        let recipsOuter = JSON.parse(recipsJson)

        let alg = recipsOuter.alg
        let isAuthcrypt = alg === 'Authcrypt'
        if (!isAuthcrypt && alg !== 'Anoncrypt') {
            throw new Error('Unsupported pack algorithm: ' + alg)
        }
        let [cek, senderVk, recipVk] = this.locateRecKey(recipsOuter.recipients, toKeys)
        if (!senderVk && isAuthcrypt) {
            throw new Error('Sender public key not provided in Authcrypt message')
        }
        let ciphertext = this.b64dec(wrapper.ciphertext)
        let nonce = this.b64dec(wrapper.iv)

        let message = this.decryptPlaintext(ciphertext, nonce, cek)
        if (message.match(JWS_REGEX)) {
            let jws_verified = this.verifyContent(message)
            const senderKey = Base58.encode(senderVk)
            return {
                message: jws_verified.content,
                recipientKey: recipVk,
                senderKey,
                nonRepudiableVerification: senderKey === jws_verified.verkey ? true : false
            }
        } else {
            return {
                message,
                recipientKey: recipVk,
                senderKey: senderVk,
                nonRepudiableVerification: false,
            }
        }
    }

    private async signContent(msg: string, SignerKeyPair: nacl.SignKeyPair) : Promise<string> {
        // get public key base58 encoded
        let senderVk = Base58.encode(SignerKeyPair.publicKey)

        // generate jose header, b64url encode it, and concat to b64url encoded payload
        let jose_header = {
            alg: 'EdDSA',
            kid: senderVk
        }
        let jose_string = JSON.stringify(jose_header);
        let b64_jose_str = this.b64url(jose_string);
        let b64_payload = this.b64url(msg);
        let header_and_payload_concat = `${b64_jose_str}.${b64_payload}`;

        //sign data and return compact JWS
        let signature = this.b64url(nacl.sign(naclutil.decodeUTF8(header_and_payload_concat), SignerKeyPair.secretKey));
        return `${header_and_payload_concat}.${signature}`;
    }

    private verifyContent(jws: string): JWSUnpacked {        
        let jws_parts = jws.match(JWS_REGEX);
        if (!jws_parts) throw new Error('Not a valid JWS')
        let jose_header = JSON.parse(this.strB64dec(jws_parts[1]));
        if (jose_header.alg != 'EdDSA') {
            throw "Cryptographic algorithm unidentifiable"
        };
        let sig_msg = nacl.sign.open(this.b64dec(jws_parts[3]), Base58.decode(jose_header.kid));

        return {
            content: this.strB64dec(jws_parts[2]),
            verkey: jose_header.kid,
            verified: sig_msg && (naclutil.encodeUTF8(sig_msg) === `${jws_parts[1]}.${jws_parts[2]}`) ? true : false
        };
    }
  
    private padB64url(base64url: string): string {
        switch (base64url.length % 4) {
        case 0: return base64url
        case 2: return base64url + '=='
        case 3: return base64url + '='
        default: throw new Error('Invalid base64url encoded string')
        }
    }
    
    private b64url(input: Uint8Array | string) {
        return naclutil.encodeBase64(input instanceof Uint8Array ? input : naclutil.decodeUTF8(input)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
    }

    private b64dec(input: string): Uint8Array {
        return naclutil.decodeBase64(this.padB64url(input).replace(/-/g, '+').replace(/_/g, '/'))
    }

    private strB64dec(input: string) : string {
        return naclutil.encodeUTF8(this.b64dec(input))
    }

    private encryptPlaintext(message: Uint8Array, key: Uint8Array) {
        let iv = nacl.randomBytes(nacl.secretbox.nonceLength)
        let ciphertext = nacl.secretbox(message, iv, key)
        return [ciphertext, iv]
    }

    private decryptPlaintext(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array) {
        const plaintext = nacl.secretbox.open(
            ciphertext,
            nonce, // npub
            key,
        )
        if (!plaintext) throw new Error('Failure Decrypting Plaintext')
        return naclutil.encodeUTF8(plaintext)
    }

    private prepareRecipientKeys(toKeys: Uint8Array[], fromKeys: nacl.SignKeyPair|null = null) {
        const cek = nacl.randomBytes(nacl.secretbox.keyLength)
        let recips: any[] = []
        let senderVk: Uint8Array | undefined
        let senderKp: nacl.BoxKeyPair | undefined

        if (fromKeys) {
            senderVk = fromKeys.publicKey
            senderKp = convertKeyPair(fromKeys)
        }
        toKeys.forEach((targetVk: Uint8Array) => {
            let encCek = null
            let encSender = null
            let nonce = null

            let targetPk = convertPublicKey(targetVk)

            if (senderVk && senderKp) {
                encSender = sealedbox.seal(senderVk, targetPk)

                nonce = nacl.randomBytes(nacl.box.nonceLength)
                encCek = nacl.box(cek, nonce, targetPk, senderKp.secretKey)
            } else {
                encCek = sealedbox.seal(cek, targetPk)
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

        let data = {
            alg: fromKeys ? 'Authcrypt' : 'Anoncrypt',
            enc: 'xsalsa20-poly1305',
            recipients: recips,
            typ: 'JWM/1.0',
        }
        return { data: JSON.stringify(data), cek }
    }

    private locateRecKey(recipients: any, keys: nacl.SignKeyPair) {
        let kp = convertKeyPair(keys)
        let myPk = Base58.encode(keys.publicKey)
        /* tslint:disable */
        for (let recip of recipients) {
            if (!('header' in recip) || !('encrypted_key' in recip)) {
                throw new Error('Invalid recipient header')
            }

            if (recip.header.kid === myPk) {
                let encryptedKey = this.b64dec(recip.encrypted_key)
                let nonce = recip.header.iv ? this.b64dec(recip.header.iv) : null
                let encSender = recip.header.sender ? this.b64dec(recip.header.sender) : null

                let senderVk = null
                let cek = null
                if (nonce && encSender) {
                    senderVk = sealedbox.open(encSender, kp.publicKey, kp.secretKey)
                    let senderPk = convertPublicKey(senderVk)
                    cek = nacl.box.open(encryptedKey, nonce, senderPk, kp.secretKey)
                } else {
                    cek = sealedbox.open(encryptedKey, kp.publicKey, kp.secretKey)
                }
                return [cek, senderVk, recip.header.kid]
            }
        }

        throw new Error('No corresponding recipient key found in recipients')
    }
}
