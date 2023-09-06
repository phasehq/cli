import base64
from typing import Tuple
from typing import List
from nacl.encoding import RawEncoder
import functools
import nacl.bindings
from nacl.encoding import HexEncoder
from nacl.public import PrivateKey
from nacl.bindings import (
    crypto_kx_keypair, 
    crypto_aead_xchacha20poly1305_ietf_encrypt, 
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    randombytes, 
    crypto_secretbox_NONCEBYTES, 
    crypto_kx_server_session_keys, 
    crypto_kx_client_session_keys,
    crypto_kx_seed_keypair,
)
from nacl.hash import blake2b
from nacl.utils import random
from base64 import b64encode, b64decode
from phase_cli.utils.network import (
    fetch_phase_user,
    fetch_phase_secrets,
    create_phase_secrets,
    update_phase_secrets,
    delete_phase_secrets
)
from phase_cli.utils.const import __ph_version__


class CryptoUtils:
    
    VERSION = 1
    
    @staticmethod
    def random_key_pair() -> Tuple[bytes, bytes]:
        """
        Generates a random key exchange keypair.

        Returns:
            Tuple[bytes, bytes]: A tuple of two bytes objects representing the public and
            private keys of the keypair.
        """
        keypair = crypto_kx_keypair()
        return keypair
    
    @staticmethod
    def client_session_keys(ephemeral_key_pair, recipient_pub_key):
        client_public_key, client_private_key = ephemeral_key_pair
        return nacl.bindings.crypto_kx_client_session_keys(
            client_public_key,
            client_private_key,
            recipient_pub_key
        )


    @staticmethod
    def server_session_keys(app_key_pair, data_pub_key):
        server_public_key, server_private_key = app_key_pair
        return nacl.bindings.crypto_kx_server_session_keys(
            server_public_key,
            server_private_key,
            data_pub_key
        )

    @staticmethod
    def encrypt_asymmetric(plaintext, public_key_hex):

        public_key, private_key = CryptoUtils.random_key_pair()

        symmetric_keys = CryptoUtils.client_session_keys((public_key, private_key), bytes.fromhex(public_key_hex))
        
        ciphertext = CryptoUtils.encrypt_string(plaintext, symmetric_keys[1])

        return f"ph:v{CryptoUtils.VERSION}:{public_key.hex()}:{ciphertext}"


    @staticmethod
    def decrypt_asymmetric(ciphertext_string, private_key_hex, public_key_hex):
        ciphertext_segments = ciphertext_string.split(':')

        if len(ciphertext_segments) != 4:
            raise ValueError('Invalid ciphertext')

        public_key = bytes.fromhex(public_key_hex)
        private_key = bytes.fromhex(private_key_hex)
        
        session_keys = CryptoUtils.server_session_keys(
            (public_key, private_key),
            bytes.fromhex(ciphertext_segments[2])
        )

        plaintext = CryptoUtils.decrypt_string(ciphertext_segments[3], session_keys[0])

        return plaintext


    @staticmethod
    def digest(input):
        hash = blake2b(input.encode(), encoder=nacl.encoding.RawEncoder)
        return base64.b64encode(hash).decode()

    @staticmethod
    def encrypt_raw(plaintext, key):
        nonce = random(nacl.bindings.crypto_secretbox_NONCEBYTES)
        ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext.encode(),
            None,   
            nonce,
            key
        )
        return bytearray(ciphertext + nonce)

    @staticmethod
    def decrypt_raw(ct, key) -> bytes:
        try:
            nonce = ct[-24:]
            ciphertext = ct[:-24]    
            plaintext_bytes = crypto_aead_xchacha20poly1305_ietf_decrypt(
                ciphertext, 
                None, 
                nonce, 
                key
            )
            return plaintext_bytes
        except Exception as e:
            print(f"Exception during decryption: {e}")
            raise ValueError('Decryption error') from e

    @staticmethod
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
        ciphertext = CryptoUtils.encrypt_raw(plaintext_bytes, key_bytes)
        return base64.b64encode(ciphertext).decode('utf-8')

    @staticmethod
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

        plaintext_bytes = CryptoUtils.decrypt_raw(ct_bytes, key_bytes)

        return plaintext_bytes.decode('utf-8')

    @staticmethod
    def encrypt_string(plaintext, key):
        return base64.b64encode(CryptoUtils.encrypt_raw(plaintext, key)).decode()

    @staticmethod
    def decrypt_string(cipherText, key):
        return CryptoUtils.decrypt_raw(base64.b64decode(cipherText), key).decode()

    @staticmethod
    def env_keypair(env_seed: str):
        """
        Derives an env keyring from the given seed

        :param env_seed: Env seed as a hex string
        :return: A dictionary containing the public and private keys in hex format
        """

        # Convert the hex seed to bytes
        seed_bytes = bytes.fromhex(env_seed)
        
        # Generate the key pair
        public_key, private_key = nacl.bindings.crypto_kx_seed_keypair(seed_bytes)
        
        # Convert the keys to hex format
        public_key_hex = public_key.hex()
        private_key_hex = private_key.hex()
        
        # Return the keys in a dictionary
        return {'publicKey': public_key_hex, 'privateKey': private_key_hex}

    @staticmethod
    def blake2b_digest(input_str: str, salt: str) -> str:
        """
        Generate a BLAKE2b hash of the input string with a salt.

        Args:
            input_str (str): The input string to be hashed.
            salt (str): The salt (key) used for hashing.

        Returns:
            str: The hexadecimal representation of the hash.
        """
        hash_size = 32  # 32 bytes (256 bits)
        hashed = blake2b(input_str.encode('utf-8'), key=salt.encode('utf-8'), encoder=nacl.encoding.RawEncoder, digest_size=hash_size)
        hex_encoded = hashed.hex()
        return hex_encoded

    @staticmethod
    def xor_bytes(a, b) -> bytes:
        """
        Computes the XOR of two byte arrays byte by byte.

        Args:
            a (bytes): The first byte array
            b (bytes): The second byte array.

        Returns:
            bytes: A byte array representing the XOR of the two input byte arrays.
        """
        return bytes(x ^ y for x, y in zip(a, b))

    @staticmethod
    def reconstruct_secret(shares) -> str:
        """
        Reconstructs a secret given an array of shares.

        Args:
            shares (list): A list of hex-encoded secret shares.

        Returns:
            str: The reconstructed secret as a hex-encoded string.
        """
        return functools.reduce(CryptoUtils.xor_bytes, [bytes.fromhex(share) for share in shares]).hex()
