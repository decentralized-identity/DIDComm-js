const _sodium = require('libsodium-wrappers');

const PROTECTED_AUTH = JSON.stringify({
    enc: "xsalsa20poly1305",
    typ: "JWM/1.0",
    aad_hash_alg: "BLAKE2b",
    cek_enc: "authcrypt"
});

const PROTECTED_ANON =  JSON.stringify({
    enc: "xsalsa20poly1305",
    typ: "JWM/1.0",
    aad_hash_alg: "BLAKE2b",
    cek_enc: "anoncrypt"
});


exports.setup = (async() => {
    await _sodium.ready;
    const sodium = _sodium;

    function b64url(input) {
        return sodium.to_base64(input, sodium.base64_variants.URLSAFE_NO_PADDING);
    }

    function b64dec(input) {
        return sodium.from_base64(input, sodium.base64_variants.URLSAFE_NO_PADDING);
    }

    function str_b64dec(input) {
        return sodium.to_string(sodium.from_base64(input, sodium.base64_variants.URLSAFE_NO_PADDING));
    }

    function encrypt_msg_with_ad(msg, ad, cek) {
        let iv = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
        let enc_res = sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(msg, ad, null, iv, cek);
        return {
            iv: iv,
            tag: enc_res.mac,
            ciphertext: enc_res.ciphertext
        };
    }

    function prepare_recipients_anon(cek, receiver_public_keys) {
        let recipients = [];
        receiver_public_keys.forEach(function(key) {
            recipients.push({
                encrypted_key: b64url(sodium.crypto_box_seal(cek, key)),
                header: {
                    kid: b64url(key)
                }

            });
        });
        return recipients;
    }

    function pack_anon(msg, receiver_public_keys) {
        let cek = sodium.crypto_aead_chacha20poly1305_ietf_keygen();
        let recipients = prepare_recipients_anon(cek, receiver_public_keys);
        let aad = b64url(sodium.crypto_generichash(sodium.crypto_generichash_BYTES_MAX, b64url(JSON.stringify(recipients))));

        let encrypt_result = encrypt_msg_with_ad(msg, aad, cek);

        let ret = {
            protected: b64url(PROTECTED_ANON),
            recipients: prepare_recipients_anon(cek, receiver_public_keys),
            aad: aad,
            iv: b64url(encrypt_result.iv),
            ciphertext: b64url(encrypt_result.ciphertext),
            tag: b64url(encrypt_result.tag)
        };

        return b64url(JSON.stringify(ret));
    }

    exports.pack = function(msg, receiver_public_keys, sender_public_key = undefined, sender_secret_key = undefined) {
        if (sender_public_key === undefined) {
            return pack_anon(msg, receiver_public_keys);
        }
    }

    function decode_packed_msg(packed_msg) {
        let decoded_msg = JSON.parse(str_b64dec(packed_msg));
        decoded_msg.protected = JSON.parse(str_b64dec(decoded_msg.protected));
        decoded_msg.recipients = decoded_msg.recipients.map(function(recipient) {
            return {
                encrypted_key: b64dec(recipient.encrypted_key),
                header: {
                    kid: b64dec(recipient.header.kid)
                }
            };
        });
        decoded_msg.aad = b64dec(decoded_msg.aad);
        decoded_msg.iv = b64dec(decoded_msg.iv);
        decoded_msg.ciphertext = b64dec(decoded_msg.ciphertext);
        decoded_msg.tag = b64dec(decoded_msg.tag);
        return decoded_msg;
    }

    function find_in_recipients(recipients, receiver_public_key) {
        let recipient = null;
        recipients.forEach(function(r) {
            if (sodium.compare(r.header.kid, receiver_public_key) === 0) {
                recipient = r;
            }
        })
        if (recipient == null) {
            throw "Key not found in recipients!";
        }
        return recipient;
    }

    function decrypt_msg_with_ad(ciphertext, tag, ad, iv, cek) {
        console.log(sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached());

    }

    function unpack_anon(msg, receiver_public_key, receiver_secret_key) {
        let recipient = find_in_recipients(msg.recipients, receiver_public_key);
        let cek = sodium.crypto_box_seal_open(recipient.encrypted_key, receiver_public_key, receiver_secret_key);
        decrypt_msg_with_ad(msg.ciphertext, msg.tag, msg.aad, msg.iv, cek);
    }

    exports.unpack = function(packed_msg, receiver_public_key, receiver_secret_key) {
        let decoded_msg = decode_packed_msg(packed_msg);
        if (decoded_msg.protected.cek_enc === "anoncrypt") {
            return unpack_anon(decoded_msg, receiver_public_key, receiver_secret_key);
        }
    }

    exports.test = function() {
        let alice = sodium.crypto_box_keypair();
        let bob = sodium.crypto_box_keypair();
        try {
            packed_msg = exports.pack("testing", [bob.publicKey]);
            exports.unpack(packed_msg, bob.publicKey, bob.privateKey);
        } catch (e) {
            console.log(e);
        }
    }
});

exports.setup().then(function() {
    exports.test();
});
