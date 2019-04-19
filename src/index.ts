import Base58 = require('base-58')
import _sodium = require('libsodium-wrappers')

const sodium = _sodium

export async function setup() {
    await _sodium.ready
}

function b64url(input: any) {
    return sodium.to_base64(input, sodium.base64_variants.URLSAFE)
}

function b64dec(input: any) {
    return sodium.from_base64(input, sodium.base64_variants.URLSAFE)
}

function strB64dec(input: any) {
    return sodium.to_string(sodium.from_base64(input, sodium.base64_variants.URLSAFE))
}

function encryptPlaintext(message: any, addData: any, key: any) {
    const iv = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
    const out = sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(message, addData, null, iv, key)
    return [out.ciphertext, out.mac, iv]
}

function decryptPlaintext(ciphertext: any, mac: any, recipsBin: any, nonce: any, key: any) {
    return sodium.to_string(
        sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            null, // nsec
            ciphertext,
            mac,
            recipsBin, // ad
            nonce, // npub
            key,
        ),
    )
}

function prepareRecipientKeys(toKeys: any, fromKeys: any = null) {
    const cek = sodium.crypto_secretstream_xchacha20poly1305_keygen()
    const recips: any[] = []

    toKeys.forEach((targetVk: any) => {
        let encCek = null
        let encSender = null
        let nonce = null

        const targetPk = sodium.crypto_sign_ed25519_pk_to_curve25519(targetVk)

        if (fromKeys) {
            const senderVk = Base58.encode(fromKeys.publicKey)
            const senderSk = sodium.crypto_sign_ed25519_sk_to_curve25519(fromKeys.privateKey)
            encSender = sodium.crypto_box_seal(senderVk, targetPk)

            nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES)
            encCek = sodium.crypto_box_easy(cek, nonce, targetPk, senderSk)
        } else {
            encCek = sodium.crypto_box_seal(cek, targetPk)
        }

        recips.push(
            {
                encrypted_key: b64url(encCek),
                header: {
                    iv: nonce ? b64url(nonce) : null,
                    kid: Base58.encode(targetVk),
                    sender: encSender ? b64url(encSender) : null,
                },
            },
        )
    })

    const data = {
        alg: fromKeys ? 'Authcrypt' : 'Anoncrypt',
        enc: 'xchacha20poly1305_ietf',
        recipients: recips,
        typ: 'JWM/1.0',
    }
    return [JSON.stringify(data), cek]
}

function locateRecKey(recipients: any[], keys: any) {
    const notFound = []
    recipients.forEach((_V, i) => {
        const recip = recipients[i]
        if (!('header' in recip) || !('encrypted_key' in recip)) {
            throw new Error('Invalid recipient header')
        }

        const recipVk = Base58.decode(recip.header.kid)
        if (!sodium.memcmp(recipVk, keys.publicKey)) {
            notFound.push(recip.header.kid)
        }
        const pk = sodium.crypto_sign_ed25519_pk_to_curve25519(keys.publicKey)
        const sk = sodium.crypto_sign_ed25519_sk_to_curve25519(keys.privateKey)

        const encrytpedKey = b64dec(recip.encrypted_key)
        const nonce = recip.header.iv ? b64dec(recip.header.iv) : null
        const encSender = recip.header.sender ? b64dec(recip.header.sender) : null

        let senderVk = null
        let cek = null
        if (nonce && encSender) {
            senderVk = sodium.to_string(sodium.crypto_box_seal_open(encSender, pk, sk))
            const senderPk = sodium.crypto_sign_ed25519_pk_to_curve25519(Base58.decode(senderVk))
            cek = sodium.crypto_box_open_easy(encrytpedKey, nonce, senderPk, sk)
        } else {
            cek = sodium.crypto_box_seal_open(encrytpedKey, pk, sk)
        }
        return [cek, senderVk, recip.header.kid]
    })

    throw new Error('No corresponding recipient key found in recipients')
}

export async function packMessage(message: any, toKeys: any, fromKeys = null) {
    const [cek, recipsJson] = prepareRecipientKeys(toKeys, fromKeys)
    const recipsB64 = b64url(recipsJson)

    const [ciphertext, tag, iv] = encryptPlaintext(message, recipsB64, cek)

    return JSON.stringify({
        ciphertext: b64url(ciphertext),
        iv: b64url(iv),
        protected: recipsB64,
        tag: b64url(tag),
    })
}

export async function unpackMessage(encMsg: any, toKeys: any) {
    if (typeof encMsg: any === 'string') {
        wrapper = JSON.parse(encMsg: any)
    } else {
        wrapper = encMsg: any
    }
    if (typeof toKeys.publicKey === 'string') {
        toKeys.publicKey = Base58.decode(toKeys.publicKey)
    }
    if (typeof toKeys.privateKey === 'string') {
        toKeys.privateKey = Base58.decode(toKeys.privateKey)
    }
    recipsJson = strB64dec(wrapper.protected)
    recips_outer = JSON.parse(recipsJson)

    alg = recips_outer.alg
    is_authcrypt = alg == 'Authcrypt'
    if (!is_authcrypt && alg != 'Anoncrypt') {
        throw new Error('Unsupported pack algorithm: ' + alg);
    }
    const [cek, senderVk, recipVk] = locateRecKey(recips_outer.recipients, toKeys)
    if (!senderVk && is_authcrypt) {
        throw new Error('Sender public key not provided in Authcrypt message');
    }
    ciphertext = b64dec(wrapper.ciphertext)
    nonce = b64dec(wrapper.iv)
    tag = b64dec(wrapper.tag)

    message = decryptPlaintext(ciphertext, tag, wrapper.protected, nonce, cek)
    return {
        message,
        sender_key: senderVk,
        recipient_key: recipVk,
    }
}

// export function test() {
//     const alice = sodium.crypto_sign_keypair()
//     const bob = sodium.crypto_sign_keypair()
//     try {
//         packed_msg = exports.pack_message('testing', [bob.publicKey], alice)
//         console.log(packed_msg)
//         console.log(exports.unpack_message(packed_msg, bob))
//     } catch (e) {
//         console.log(e)
//     }
// }
