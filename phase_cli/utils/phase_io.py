import base64
import requests, json
from typing import Tuple
from typing import List
from dataclasses import dataclass
from phase_cli.utils.network import (
    fetch_phase_user,
    fetch_wrapped_key_share,
    fetch_phase_secrets,
    create_phase_secrets,
    update_phase_secrets,
    delete_phase_secrets
)
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
from phase_cli.utils.crypto import CryptoUtils
from phase_cli.utils.const import __ph_version__, PHASE_ENV_CONFIG, pss_user_pattern, pss_service_pattern
from phase_cli.utils.misc import phase_get_context, get_default_user_host
from phase_cli.utils.keyring import get_credentials

@dataclass
class AppSecret:
    prefix: str
    pes_version: str
    app_token: str
    pss_user_public_key: str
    keyshare0: str
    keyshare1_unwrap_key: str


class Phase:
    _app_pub_key = ''
    _api_host = ''
    _app_secret = None

    def __init__(self):
        
        app_secret = get_credentials()
        self._api_host = get_default_user_host()

        # Determine the type of the token (service token or user token)
        self.is_service_token = pss_service_pattern.match(app_secret) is not None
        self.is_user_token = pss_user_pattern.match(app_secret) is not None

        # If it's neither a service token nor a user token, raise an error
        if not self.is_service_token and not self.is_user_token:
            token_type = "service token" if "pss_service" in app_secret else "user token"
            raise ValueError(f"Invalid Phase {token_type}")

        # Storing the token type as a string for easier access
        self._token_type = "service" if self.is_service_token else "user"

        pss_segments = app_secret.split(':')
        self._app_secret = AppSecret(*pss_segments)

    def _find_matching_environment_key(self, user_data, env_id):
        for app in user_data.get("apps", []):
            for environment_key in app.get("environment_keys", []):
                if environment_key["environment"]["id"] == env_id:
                    return environment_key
        return None

    def auth(self):
        try:
            key = fetch_app_key(
                self._token_type, self._app_secret.app_token, self._app_secret.keyshare1_unwrap_key, self._api_host)

            return "Success"

        except ValueError as err:
            raise ValueError(f"Invalid Phase credentials")

    def init(self):
        response = fetch_phase_user(self._token_type, self._app_secret.app_token, self._api_host)

        # Ensure the response is OK
        if response.status_code != 200:
            raise ValueError(f"Request failed with status code {response.status_code}: {response.text}")
        
        # Parse and return the JSON content
        return response.json()


    def create(self, key_value_pairs: List[Tuple[str, str]], env_name: str, app_name: str) -> requests.Response:
        """
        Create secrets in Phase KMS.
        
        Args:
            key_value_pairs (List[Tuple[str, str]]): List of tuples where each tuple contains a key and a value.
            env_name (str): The name (or partial name) of the desired environment.
                
        Returns:
            requests.Response: The HTTP response from the Phase KMS.
        """
        user_response = fetch_phase_user(self._token_type, self._app_secret.app_token, self._api_host)
        if user_response.status_code != 200:
            raise ValueError(f"Request failed with status code {user_response.status_code}: {user_response.text}")

        user_data = user_response.json()
        app_id, env_id, public_key = phase_get_context(user_data, app_name=app_name, env_name=env_name)
        
        environment_key = self._find_matching_environment_key(user_data, env_id)
        if environment_key is None:
            raise ValueError(f"No environment found with id: {env_id}")

        wrapped_salt = environment_key.get("wrapped_salt")
        decrypted_salt = self.decrypt(wrapped_salt)

        secrets = []
        for key, value in key_value_pairs:
            encrypted_key = CryptoUtils.encrypt_asymmetric(key, public_key)
            encrypted_value = CryptoUtils.encrypt_asymmetric(value, public_key)
            key_digest = CryptoUtils.blake2b_digest(key, decrypted_salt)
            
            secret = {
                "key": encrypted_key,
                "keyDigest": key_digest,
                "value": encrypted_value,
                "folderId": None,
                "tags": [],
                "comment": ""
            }
            secrets.append(secret)

        return create_phase_secrets(self._token_type, self._app_secret.app_token, env_id, secrets, self._api_host)


    def get(self, env_name: str, key: str = None, app_name: str = None):
        """
        Get secrets from Phase KMS based on key and environment.
        
        Args:
            key (str, optional): The key for which to retrieve the secret value.
            env_name (str): The name (or partial name) of the desired environment.
            app_name (str, optional): The name of the desired application.
                
        Returns:
            dict or list: A dictionary containing the decrypted key and value if key is provided, 
                        otherwise a list of dictionaries for all secrets in the environment.
        """
        
        user_response = fetch_phase_user(self._token_type, self._app_secret.app_token, self._api_host)
        if user_response.status_code != 200:
            raise ValueError(f"Request failed with status code {user_response.status_code}: {user_response.text}")

        user_data = user_response.json()
        app_id, env_id, public_key = phase_get_context(user_data, app_name=app_name, env_name=env_name)

        environment_key = self._find_matching_environment_key(user_data, env_id)
        if environment_key is None:
            raise ValueError(f"No environment found with id: {env_id}")

        wrapped_seed = environment_key.get("wrapped_seed")
        decrypted_seed = self.decrypt(wrapped_seed)
        key_pair = CryptoUtils.env_keypair(decrypted_seed)
        env_private_key = key_pair['privateKey']

        secrets_response = fetch_phase_secrets(self._token_type, self._app_secret.app_token, env_id, self._api_host)
        secrets_data = secrets_response.json()

        if key:
            salt = self.decrypt(environment_key.get("wrapped_salt"))
            key_digest = CryptoUtils.blake2b_digest(key, salt)

            matching_secret = next((item for item in secrets_data if item["key_digest"] == key_digest), None)
            if not matching_secret:
                raise ValueError(f"No matching secret found for digest: {key_digest}")

            decrypted_key = CryptoUtils.decrypt_asymmetric(matching_secret["key"], env_private_key, public_key)
            decrypted_value = CryptoUtils.decrypt_asymmetric(matching_secret["value"], env_private_key, public_key)

            return {"key": decrypted_key, "value": decrypted_value}
        else:
            results = []
            for secret in secrets_data:
                decrypted_key = CryptoUtils.decrypt_asymmetric(secret["key"], env_private_key, public_key)
                decrypted_value = CryptoUtils.decrypt_asymmetric(secret["value"], env_private_key, public_key)
                results.append({"key": decrypted_key, "value": decrypted_value})

            return results


    def update(self, env_name: str, key: str, value: str, app_name: str = None) -> str:
        """
        Update a secret in Phase KMS based on key and environment.
        
        Args:
            env_name (str): The name (or partial name) of the desired environment.
            key (str): The key for which to update the secret value.
            value (str): The new value for the secret.
            app_name (str, optional): The name of the desired application.
                
        Returns:
            str: A message indicating the outcome of the update operation.
        """
        
        user_response = fetch_phase_user(self._token_type, self._app_secret.app_token, self._api_host)
        if user_response.status_code != 200:
            raise ValueError(f"Request failed with status code {user_response.status_code}: {user_response.text}")

        user_data = user_response.json()
        app_id, env_id, public_key = phase_get_context(user_data, app_name=app_name, env_name=env_name)

        environment_key = self._find_matching_environment_key(user_data, env_id)
        if environment_key is None:
            raise ValueError(f"No environment found with id: {env_id}")

        secrets_response = fetch_phase_secrets(self._token_type, self._app_secret.app_token, env_id, self._api_host)
        secrets_data = secrets_response.json()

        wrapped_seed = environment_key.get("wrapped_seed")
        decrypted_seed = self.decrypt(wrapped_seed)
        key_pair = CryptoUtils.env_keypair(decrypted_seed)
        env_private_key = key_pair['privateKey']

        matching_secret = None
        for secret in secrets_data:
            decrypted_key = CryptoUtils.decrypt_asymmetric(secret["key"], env_private_key, public_key)
            if decrypted_key == key:
                matching_secret = secret
                break

        if not matching_secret:
            return f"Key '{key}' doesn't exist."

        encrypted_key = CryptoUtils.encrypt_asymmetric(key, public_key)
        encrypted_value = CryptoUtils.encrypt_asymmetric(value, public_key)
        
        wrapped_salt = environment_key.get("wrapped_salt")
        decrypted_salt = self.decrypt(wrapped_salt)
        key_digest = CryptoUtils.blake2b_digest(key, decrypted_salt)

        secret_update_payload = {
            "id": matching_secret["id"],
            "key": encrypted_key,
            "keyDigest": key_digest,
            "value": encrypted_value,
            "folderId": None,
            "tags": [],
            "comment": ""
        }

        response = update_phase_secrets(self._token_type, self._app_secret.app_token, env_id, [secret_update_payload], self._api_host)

        if response.status_code == 200:
            return "Success"
        else:
            return f"Error: Failed to update secret. HTTP Status Code: {response.status_code}"


    def delete(self, env_name: str, keys_to_delete: List[str], app_name: str = None) -> List[str]:
        """
        Delete secrets in Phase KMS based on keys and environment.
        
        Args:
            env_name (str): The name (or partial name) of the desired environment.
            keys_to_delete (List[str]): The keys for which to delete the secrets.
            app_name (str, optional): The name of the desired application.
                
        Returns:
            List[str]: A list of keys that were not found and could not be deleted.
        """
        
        user_response = fetch_phase_user(self._token_type, self._app_secret.app_token, self._api_host)
        if user_response.status_code != 200:
            raise ValueError(f"Request failed with status code {user_response.status_code}: {user_response.text}")

        user_data = user_response.json()
        app_id, env_id, public_key = phase_get_context(user_data, app_name=app_name, env_name=env_name)

        environment_key = self._find_matching_environment_key(user_data, env_id)
        if environment_key is None:
            raise ValueError(f"No environment found with id: {env_id}")

        wrapped_seed = environment_key.get("wrapped_seed")
        decrypted_seed = self.decrypt(wrapped_seed)
        key_pair = CryptoUtils.env_keypair(decrypted_seed)
        env_private_key = key_pair['privateKey']

        secret_ids_to_delete = []
        keys_not_found = []
        secrets_response = fetch_phase_secrets(self._token_type, self._app_secret.app_token, env_id, self._api_host)
        secrets_data = secrets_response.json()
            
        for key in keys_to_delete:
            found = False
            for secret in secrets_data:
                decrypted_key = CryptoUtils.decrypt_asymmetric(secret["key"], env_private_key, public_key)
                if decrypted_key == key:
                    secret_ids_to_delete.append(secret["id"])
                    found = True
                    break
            if not found:
                keys_not_found.append(key)

        delete_phase_secrets(self._token_type, self._app_secret.app_token, env_id, secret_ids_to_delete, self._api_host)
            
        return keys_not_found


    # TODO: Remove
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
                one_time_keypair[0], one_time_keypair[1], bytes.fromhex(self._app_secret.pss_user_public_key))
            ciphertext = CryptoUtils.encrypt_b64(plaintext, symmetric_keys[1])
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
            [prefix, version, client_pub_key_hex, ct] = phase_ciphertext.split(':')
            if prefix != 'ph' or len(phase_ciphertext.split(':')) != 4:
                raise ValueError('Ciphertext is invalid')
            client_pub_key = bytes.fromhex(client_pub_key_hex)

            wrapped_key_share = fetch_wrapped_key_share(
                self._token_type, self._app_secret.app_token, self._api_host)
            keyshare1 = CryptoUtils.decrypt_raw(bytes.fromhex(wrapped_key_share), bytes.fromhex(self._app_secret.keyshare1_unwrap_key)).decode("utf-8")

            app_priv_key = CryptoUtils.reconstruct_secret(
                [self._app_secret.keyshare0, keyshare1])

            session_keys = crypto_kx_server_session_keys(bytes.fromhex(
                self._app_secret.pss_user_public_key), bytes.fromhex(app_priv_key), client_pub_key)

            plaintext = CryptoUtils.decrypt_b64(ct, session_keys[0].hex())

            return plaintext

        except ValueError as err:
            raise ValueError(f"Something went wrong: {err}")
