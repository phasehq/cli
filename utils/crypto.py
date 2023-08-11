def random_key_pair() -> Tuple[bytes, bytes]:
    """
    Generates a random key exchange keypair.

    Returns:
        Tuple[bytes, bytes]: A tuple of two bytes objects representing the public and
        private keys of the keypair.
    """
    keypair = crypto_kx_keypair()
    return keypair


def encrypt(self, plaintext, tag="") -> str | None:
    """
    Encrypts a plaintext string.

    Args:
        plaintext (str): The plaintext to encrypt.
        tag (str, optional): A tag to include in the encrypted message. The tag will not be encrypted.

    Returns:
        str: The encrypted message, formatted as a string that includes the public key used for the one-time keypair, 
        the ciphertext, and the tag. Returns `None` if an error occurs.
    """
    try:
        one_time_keypair = random_key_pair()
        symmetric_keys = crypto_kx_client_session_keys(
            one_time_keypair[0], one_time_keypair[1], bytes.fromhex(self._app_pub_key))
        ciphertext = encrypt_b64(plaintext, symmetric_keys[1])
        pub_key = one_time_keypair[0].hex()

        return f"ph:{__ph_version__}:{pub_key}:{ciphertext}:{tag}"
    except ValueError as err:
        raise ValueError(f"Something went wrong: {err}")


def decrypt(self, phase_ciphertext) -> str | None:
    """
    Decrypts a Phase ciphertext string.

    Args:
        phase_ciphertext (str): The encrypted message to decrypt.

    Returns:
        str: The decrypted plaintext as a string. Returns `None` if an error occurs.

    Raises:
        ValueError: If the ciphertext is not in the expected format (e.g. wrong prefix, wrong number of fields).
    """

    try:
        [prefix, version, client_pub_key_hex, ct,
            tag] = phase_ciphertext.split(':')
        if prefix != 'ph' or len(phase_ciphertext.split(':')) != 5:
            raise ValueError('Ciphertext is invalid')
        client_pub_key = bytes.fromhex(client_pub_key_hex)

        keyshare1 = fetch_app_key(
            self._app_secret.app_token, self._app_secret.keyshare1_unwrap_key, self._app_id, len(ct)/2, self._kms_host)

        app_priv_key = reconstruct_secret(
            [self._app_secret.keyshare0, keyshare1])

        session_keys = crypto_kx_server_session_keys(bytes.fromhex(
            self._app_pub_key), bytes.fromhex(app_priv_key), client_pub_key)

        plaintext = decrypt_b64(ct, session_keys[0].hex())

        return plaintext


def encrypt_raw(plaintext, key) -> bytes:
    """
    Encrypts plaintext with the given key and returns the ciphertext with appended nonce

    Args:
        plaintext (bytes): Plaintext to be encrypted
        key (bytes): The encryption key to be used

    Returns:
        bytes: ciphertext + nonce
    """
    try:
        nonce = randombytes(crypto_secretbox_NONCEBYTES)
        ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, None, nonce, key)
        return ciphertext + nonce
    except Exception:
        raise ValueError('Encryption error')


def encrypt_b64(plaintext, key_bytes) -> str:
    """
    Encrypts a string using a key. Returns ciphertext as a base64 string

    Args:
        plaintext (str): The plaintext to encrypt.
        key (bytes): The key to use for encryption.

    Returns:
        str: The ciphertext obtained by encrypting the string with the key, encoded with base64.
    """

    plaintext_bytes = bytes(plaintext, 'utf-8')
    ciphertext = encrypt_raw(plaintext_bytes, key_bytes)
    return base64.b64encode(ciphertext).decode('utf-8')


def decrypt_raw(ct, key) -> bytes:
    """
    Decrypts a ciphertext using a key.

    Args:
        ct (bytes): The ciphertext to decrypt.
        key (bytes): The key to use for decryption, as a hexadecimal string.

    Returns:
        bytes: The plaintext obtained by decrypting the ciphertext with the key.
    """

    try:
        nonce = ct[-24:]
        ciphertext = ct[:-24]

        plaintext_bytes = crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, None, nonce, key)

        return plaintext_bytes
    except Exception:
        raise ValueError('Decryption error')


def decrypt_b64(ct, key) -> bytes:
    """
    Decrypts a base64 ciphertext using a key.

    Args:
        ct (str): The ciphertext to decrypt, as a base64 string.
        key (str): The key to use for decryption, as a hexadecimal string.

    Returns:
        str: The plaintext obtained by decrypting the ciphertext with the key.
    """

    ct_bytes = base64.b64decode(ct)
    key_bytes = bytes.fromhex(key)

    plaintext_bytes = decrypt_raw(ct_bytes, key_bytes)

    return plaintext_bytes.decode('utf-8')