const _sodium = require('libsodium-wrappers');
const Base58 = require('base-58');

exports.setup = (async() => {
    await _sodium.ready;
    const sodium = _sodium;

    function b64url(input) {
        return sodium.to_base64(input, sodium.base64_variants.URLSAFE);
    }

    function b64dec(input) {
        return sodium.from_base64(input, sodium.base64_variants.URLSAFE);
    }

    function str_b64dec(input) {
        return sodium.to_string(sodium.from_base64(input, sodium.base64_variants.URLSAFE));
    }

    function encrypt_plaintext(message, add_data, key) {
        let iv = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
        let out = sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(message, add_data, null, iv, key);
        return [out.ciphertext, out.mac, iv];
    }

    function decrypt_plaintext(ciphertext, mac, recips_bin, nonce, key) {
        return sodium.to_string(
            sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(
                null, //nsec
                ciphertext,
                mac,
                recips_bin, //ad
                nonce, //npub
                key
            )
        );
    }

    function prepare_recipient_keys(to_keys, from_keys = null) {
        cek = sodium.crypto_secretstream_xchacha20poly1305_keygen();
        recips = [];

        to_keys.forEach(function(target_vk) {
            let enc_cek = null;
            let enc_sender = null;
            let nonce = null;

            let target_pk = sodium.crypto_sign_ed25519_pk_to_curve25519(target_vk);

            if (from_keys) {
                let sender_vk = Base58.encode(from_keys.publicKey);
                let sender_sk = sodium.crypto_sign_ed25519_sk_to_curve25519(from_keys.privateKey);
                enc_sender = sodium.crypto_box_seal(sender_vk, target_pk);

                nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
                enc_cek = sodium.crypto_box_easy(cek, nonce, target_pk, sender_sk);
            } else {
                enc_cek = sodium.crypto_box_seal(cek, target_pk);
            }

            recips.push(
                {
                    encrypted_key: b64url(enc_cek),
                    header: {
                        kid: Base58.encode(target_vk),
                        sender: enc_sender ? b64url(enc_sender) : null,
                        iv: nonce ? b64url(nonce) : null
                    }
                }
            );
        });

        data = {
            enc: 'xchacha20poly1305_ietf',
            typ: 'JWM/1.0',
            alg: from_keys ? 'Authcrypt' : "Anoncrypt",
            recipients: recips
        }
        return [JSON.stringify(data), cek]
    }

    function locate_recipient_key(recipients, keys) {
        not_found = [];
        for (let index in recipients) {
            let recip = recipients[index];
            if (!('header' in recip) || !('encrypted_key' in recip)) {
                throw 'Invalid recipient header';
            }

            let recip_vk = Base58.decode(recip.header.kid);
            if (!sodium.memcmp(recip_vk, keys.publicKey)) {
                not_found.push(recip.header.kid);
                continue;
            }
            let pk = sodium.crypto_sign_ed25519_pk_to_curve25519(keys.publicKey);
            let sk = sodium.crypto_sign_ed25519_sk_to_curve25519(keys.privateKey);

            let encrytped_key = b64dec(recip.encrypted_key);
            let nonce = recip.header.iv ? b64dec(recip.header.iv) : null;
            let enc_sender = recip.header.sender ? b64dec(recip.header.sender) : null;

            let sender_vk = null;
            let cek = null;
            if (nonce && enc_sender) {
                sender_vk = sodium.to_string(sodium.crypto_box_seal_open(enc_sender, pk, sk));
                let sender_pk = sodium.crypto_sign_ed25519_pk_to_curve25519(Base58.decode(sender_vk));
                cek = sodium.crypto_box_open_easy(encrytped_key, nonce, sender_pk, sk);
            } else {
                cek = sodium.crypto_box_seal_open(encrytped_key, pk, sk);
            }
            return [cek, sender_vk, recip.header.kid];
        }

        throw "No corresponding recipient key found in recipients";
    }

    exports.pack_message = function(message, to_keys, from_keys = null) {
        let [recips_json, cek] = prepare_recipient_keys(to_keys, from_keys);
        recips_b64 = b64url(recips_json);

        let [ciphertext, tag, iv] = encrypt_plaintext(message, recips_b64, cek);

        return JSON.stringify({
            protected: recips_b64,
            iv: b64url(iv),
            ciphertext: b64url(ciphertext),
            tag: b64url(tag)
        });
    }

    exports.unpack_message = function(enc_message, to_keys) {
        if (typeof enc_message === 'string'){
            wrapper = JSON.parse(enc_message);
        } else {
            wrapper = enc_message;
        }
        if (typeof to_keys.publicKey === 'string'){
            to_keys.publicKey = Base58.decode(to_keys.publicKey);
        }
        if (typeof to_keys.privateKey === 'string'){
            to_keys.privateKey = Base58.decode(to_keys.privateKey);
        }
        recips_json = str_b64dec(wrapper.protected);
        recips_outer = JSON.parse(recips_json);

        alg = recips_outer.alg;
        is_authcrypt = alg == 'Authcrypt';
        if (!is_authcrypt && alg != 'Anoncrypt') {
            throw 'Unsupported pack algorithm: ' + alg;
        }
        let [cek, sender_vk, recip_vk] = locate_recipient_key(recips_outer.recipients, to_keys);
        if (!sender_vk && is_authcrypt) {
            throw 'Sender public key not provided in Authcrypt message';
        }
        ciphertext = b64dec(wrapper.ciphertext);
        nonce = b64dec(wrapper.iv);
        tag = b64dec(wrapper.tag);

        message = decrypt_plaintext(ciphertext, tag, wrapper.protected, nonce, cek);
        return {
            message: message,
            sender_key: sender_vk,
            recipient_key: recip_vk
        };
    }

    exports.test = function() {
        let alice = sodium.crypto_sign_keypair();
        let bob = sodium.crypto_sign_keypair();
        try {
            packed_msg = exports.pack_message("testing", [bob.publicKey], alice);
            console.log(packed_msg);
            console.log(exports.unpack_message(packed_msg, bob));
        } catch (e) {
            console.log(e);
        }
    }
});

exports.setup().then(function() {
    exports.test();
});
