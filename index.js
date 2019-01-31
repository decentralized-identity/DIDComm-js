const _sodium = require('libsodium-wrappers');
const Base58 = require('base-58');

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

    function create_keypair(seed = null) {
        if (!seed) {
            seed = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
        }
        res = sodium.crypto_box_seed_keypair(seed);
        return [res.publicKey, res.privateKey];
    }

    function prepare_recipient_keys(to_keys, from_keys = null) {
        cek = sodium.crypto_secretstream_xchacha20poly1305_keygen();
        recips = [];

        to_keys.forEach(function(target_vk) {
            let enc_cek = null;
            let enc_sender = null;
            let nonce = null;

            if (from_keys) {
                let sender_vk = Base58.encode(from_keys.publicKey);
                enc_sender = sodium.crypto_box_seal(sender_vk, target_vk);

                nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
                enc_cek = sodium.crypto_box_easy(cek, nonce, target_vk, from_keys.privateKey);
            } else {
                enc_cek = sodium.crypto_box_seal(cek, target_vk);
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

    // def locate_recipient_key(recipients: Sequence[dict], find_key: Callable) \
    //         -> (bytes, str, str):
    //     """
    //     Decode the encryption key and sender verification key from a
    //     corresponding recipient block, if any is defined
    //     """
    //     not_found = []
    //     for recip in recipients:
    //         if not recip or "header" not in recip or "encrypted_key" not in recip:
    //             raise ValueError("Invalid recipient header")
    //
    //         recip_vk_b58 = recip["header"].get("kid")
    //         secret = find_key(recip_vk_b58)
    //         if secret is None:
    //             not_found.append(recip_vk_b58)
    //             continue
    //         recip_vk = b58_to_bytes(recip_vk_b58)
    //         pk = pysodium.crypto_sign_pk_to_box_pk(recip_vk)
    //         sk = pysodium.crypto_sign_sk_to_box_sk(secret)
    //
    //         encrypted_key = b64_to_bytes(recip["encrypted_key"], urlsafe=True)
    // 
    //         nonce_b64 = recip["header"].get("iv")
    //         nonce = b64_to_bytes(nonce_b64, urlsafe=True) if nonce_b64 else None
    //         sender_b64 = recip["header"].get("sender")
    //         enc_sender = b64_to_bytes(sender_b64, urlsafe=True) if sender_b64 else None
    // 
    //         if nonce and enc_sender:
    //             sender_vk_bin = pysodium.crypto_box_seal_open(enc_sender, pk, sk)
    //             sender_vk = sender_vk_bin.decode("ascii")
    //             sender_pk = pysodium.crypto_sign_pk_to_box_pk(b58_to_bytes(sender_vk_bin))
    //             cek = pysodium.crypto_box_open(
    //                 encrypted_key,
    //                 nonce,
    //                 sender_pk,
    //                 sk,
    //             )
    //         else:
    //             sender_vk = None
    //             cek = pysodium.crypto_box_seal_open(encrypted_key, pk, sk)
    //         return cek, sender_vk, recip_vk_b58
    //      raise ValueError("No corresponding recipient key found in {}".format(not_found))
    function locate_recipient_key(recipients, key, secret) {
        not_found = [];
        for (let index in recipients) {
            let recip = recipients[index];
            if (!('header' in recip) || !('encrypted_key' in recip)) {
                throw 'Invalid recipient header';
            }

            let recip_vk = Base58.decode(recip.header.kid);
            if (!sodium.memcmp(recip_vk, key)) {
                not_found.push(recip.header.kid);
                continue;
            }
            let pk = recip_vk;
            let sk = secret;

            let encrytped_key = b64dec(recip.encrypted_key);
            let nonce = recip.header.iv ? b64dec(recip.header.iv) : null;
            let enc_sender = recip.header.sender ? b64dec(recip.header.sender) : null;

            let sender_vk = null;
            let cek = null;
            if (nonce && enc_sender) {
                sender_vk = sodium.to_string(sodium.crypto_box_seal_open(enc_sender, pk, sk));
                let sender_pk = Base58.decode(sender_vk);
                console.log(sender_pk, sk);
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

    //def decode_pack_message(enc_message: bytes, find_key: Callable) -> (str, Optional[str], str):
    //    """
    //    Disassemble and unencrypt a packed message, returning the message content,
    //    verification key of the sender (if available), and verification key of the recipient
    //    """
    //    wrapper = json.loads(enc_message)
    //    protected_bin = wrapper["protected"].encode("ascii")
    //    recips_json = b64_to_bytes(wrapper["protected"], urlsafe=True).decode("ascii")
    //    recips_outer = json.loads(recips_json)
    //
    //    alg = recips_outer["alg"]
    //    is_authcrypt = alg == "Authcrypt"
    //    if not is_authcrypt and alg != "Anoncrypt":
    //        raise ValueError("Unsupported pack algorithm: {}".format(alg))
    //    cek, sender_vk, recip_vk = locate_recipient_key(recips_outer["recipients"], find_key)
    //    if not sender_vk and is_authcrypt:
    //        raise ValueError("Sender public key not provided for Authcrypt message")
    //
    //    ciphertext = b64_to_bytes(wrapper["ciphertext"], urlsafe=True)
    //    nonce = b64_to_bytes(wrapper["iv"], urlsafe=True)
    //    tag = b64_to_bytes(wrapper["tag"], urlsafe=True)
    //
    //    payload_bin = ciphertext + tag
    //    message = decrypt_plaintext(payload_bin, protected_bin, nonce, cek)
    //
    //    return message, sender_vk, recip_vk
    exports.unpack_message = function(enc_message, to_keys) {
        wrapper = JSON.parse(enc_message);
        recips_json = str_b64dec(wrapper.protected);
        recips_outer = JSON.parse(recips_json);

        alg = recips_outer.alg;
        is_authcrypt = alg == 'Authcrypt';
        if (!is_authcrypt && alg != 'Anoncrypt') {
            throw 'Unsupported pack algorithm: ' + alg;
        }
        let [cek, sender_vk, recip_vk] = locate_recipient_key(recips_outer.recipients, to_keys.publicKey, to_keys.privateKey);
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
        let alice = sodium.crypto_box_keypair();
        let bob = sodium.crypto_box_keypair();
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
