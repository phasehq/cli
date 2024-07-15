import requests
from typing import Tuple
from typing import List, Dict
from dataclasses import dataclass
from phase_cli.utils.network import (
    fetch_phase_user,
    fetch_app_key,
    fetch_wrapped_key_share,
    fetch_phase_secrets,
    create_phase_secrets,
    update_phase_secrets,
    delete_phase_secrets
)
from nacl.bindings import (
    crypto_kx_server_session_keys, 
)
from phase_cli.utils.crypto import CryptoUtils
from phase_cli.utils.const import __ph_version__, pss_user_pattern, pss_service_pattern
from phase_cli.utils.misc import phase_get_context, get_default_user_host, normalize_tag, tag_matches
from phase_cli.utils.keyring import get_credentials
from phase_cli.exceptions import OverrideNotFoundException

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


    def __init__(self, init=True, pss=None, host=None):
        """
        Initializes the Phase class with optional parameters.

        Parameters:
            - init (bool): Whether to initialize using default methods or use provided parameters.
            - pss (str): The Phase user token. Used if init is False.
            - host (str): The host URL. Used if init is False.
        """

        if init:
            app_secret = get_credentials()
            self._api_host = get_default_user_host()
        else:
            if not pss or not host:
                raise ValueError("Both pss and host must be provided when init is set to False.")
            app_secret = pss
            self._api_host = host

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
                self._token_type, self._app_secret.app_token, self._api_host)

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


    def create(self, key_value_pairs: List[Tuple[str, str]], env_name: str, app_name: str, path: str = '/', override_value: str = None) -> requests.Response:
        """
        Create secrets in Phase KMS with support for specifying a path and overrides.

        Args:
            key_value_pairs (List[Tuple[str, str]]): List of tuples where each tuple contains a key and a value.
            env_name (str): The name (or partial name) of the desired environment.
            app_name (str): The name of the application context.
            path (str, optional): The path under which to store the secrets. Defaults to the root path '/'.
            override_value (str, optional): The overridden value for the secret. Defaults to None.

        Returns:
            requests.Response: The HTTP response from the Phase KMS.
        """
        user_response = fetch_phase_user(self._token_type, self._app_secret.app_token, self._api_host)
        if user_response.status_code != 200:
            raise ValueError(f"Request failed with status code {user_response.status_code}: {user_response.text}")

        user_data = user_response.json()
        app_name, app_id, env_name, env_id, public_key = phase_get_context(user_data, app_name=app_name, env_name=env_name)

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
                "path": path,
                "tags": [],  # TODO: Implement tags and comments creation
                "comment": ""
            }

            if override_value:
                encrypted_override_value = CryptoUtils.encrypt_asymmetric(override_value, public_key)
                secret["override"] = {
                    "value": encrypted_override_value,
                    "isActive": True
                }

            secrets.append(secret)

        return create_phase_secrets(self._token_type, self._app_secret.app_token, env_id, secrets, self._api_host)


    def get(self, env_name: str, keys: List[str] = None, app_name: str = None, tag: str = None, path: str = '') -> List[Dict]:
        """
        Get secrets from Phase KMS based on key and environment, with support for personal overrides,
        optional tag matching, decrypting comments, and now including path support and key digest optimization.

        Args:
            env_name (str): The name (or partial name) of the desired environment.
            keys (List[str], optional): The keys for which to retrieve the secret values.
            app_name (str, optional): The name of the desired application.
            tag (str, optional): The tag to match against the secrets.
            path (str, optional): The path under which to fetch secrets, default is root.

        Returns:
            List[Dict]: A list of dictionaries for all secrets in the environment that match the criteria, including their paths.
        """
        
        user_response = fetch_phase_user(self._token_type, self._app_secret.app_token, self._api_host)
        if user_response.status_code != 200:
            raise ValueError(f"Request failed with status code {user_response.status_code}: {user_response.text}")

        user_data = user_response.json()
        app_name, app_id, env_name, env_id, public_key = phase_get_context(user_data, app_name=app_name, env_name=env_name)

        environment_key = self._find_matching_environment_key(user_data, env_id)
        if environment_key is None:
            raise ValueError("No environment found with id: {}".format(env_id))

        wrapped_seed = environment_key.get("wrapped_seed")
        decrypted_seed = self.decrypt(wrapped_seed)
        key_pair = CryptoUtils.env_keypair(decrypted_seed)
        env_private_key = key_pair['privateKey']

        params = {"path": path}
        if keys and len(keys) == 1:
            wrapped_salt = environment_key.get("wrapped_salt")
            decrypted_salt = self.decrypt(wrapped_salt)
            key_digest = CryptoUtils.blake2b_digest(keys[0], decrypted_salt)
            params["key_digest"] = key_digest

        secrets_response = fetch_phase_secrets(self._token_type, self._app_secret.app_token, env_id, self._api_host, **params)

        secrets_data = secrets_response.json()

        results = []
        for secret in secrets_data:
            # Check if a tag filter is applied and if the secret has the correct tags.
            if tag and not tag_matches(secret.get("tags", []), tag):
                continue

            secret_id = secret["id"]
            override = secret.get("override")
            # Check if the override exists and is active.
            use_override = override and override.get("is_active")

            key_to_decrypt = secret["key"]
            # Select the correct value based on override status.
            value_to_decrypt = override["value"] if use_override else secret["value"]
            comment_to_decrypt = secret["comment"]

            decrypted_key = CryptoUtils.decrypt_asymmetric(key_to_decrypt, env_private_key, public_key)
            decrypted_value = CryptoUtils.decrypt_asymmetric(value_to_decrypt, env_private_key, public_key)
            decrypted_comment = CryptoUtils.decrypt_asymmetric(comment_to_decrypt, env_private_key, public_key) if comment_to_decrypt else None

            result = {
                "key": decrypted_key,
                "value": decrypted_value,
                "overridden": use_override,
                "tags": secret.get("tags", []),
                "comment": decrypted_comment,
                "path": secret.get("path", "/"),
                "application": app_name,
                "environment": env_name 
            }

            # Only add the secret to results if the requested keys are not specified or the decrypted key is one of the requested keys.
            if not keys or decrypted_key in keys:
                results.append(result)

        return results


    def update(self, env_name: str, key: str, value: str = None, app_name: str = None, source_path: str = '', destination_path: str = None, override: bool = False, toggle_override: bool = False) -> str:
        """
        Update a secret in Phase KMS based on key and environment, with support for source and destination paths.
        
        Args:
            env_name (str): The name (or partial name) of the desired environment.
            key (str): The key for which to update the secret value.
            value (str, optional): The new value for the secret. Defaults to None.
            app_name (str, optional): The name of the desired application.
            source_path (str, optional): The current path of the secret. Defaults to root path '/'.
            destination_path (str, optional): The new path for the secret, if changing its location. If not provided, the path is not updated.
            override (bool, optional): Whether to update an overridden secret value. Defaults to False.
            toggle_override (bool, optional): Whether to toggle the override state between active and inactive. Defaults to False.
                
        Returns:
            str: A message indicating the outcome of the update operation.
        """
        
        user_response = fetch_phase_user(self._token_type, self._app_secret.app_token, self._api_host)
        if user_response.status_code != 200:
            raise ValueError(f"Request failed with status code {user_response.status_code}: {user_response.text}")

        user_data = user_response.json()
        app_name, app_id, env_name, env_id, public_key = phase_get_context(user_data, app_name=app_name, env_name=env_name)

        environment_key = self._find_matching_environment_key(user_data, env_id)
        if environment_key is None:
            raise ValueError(f"No environment found with id: {env_id}")

        # Fetch secrets from the specified source path
        secrets_response = fetch_phase_secrets(self._token_type, self._app_secret.app_token, env_id, self._api_host, path=source_path)
        secrets_data = secrets_response.json()

        wrapped_seed = environment_key.get("wrapped_seed")
        decrypted_seed = self.decrypt(wrapped_seed)
        key_pair = CryptoUtils.env_keypair(decrypted_seed)
        env_private_key = key_pair['privateKey']

        matching_secret = next((secret for secret in secrets_data if CryptoUtils.decrypt_asymmetric(secret["key"], env_private_key, public_key) == key), None)
        if not matching_secret:
            return f"Key '{key}' doesn't exist in path '{source_path}'."

        encrypted_key = CryptoUtils.encrypt_asymmetric(key, public_key)
        encrypted_value = CryptoUtils.encrypt_asymmetric(value or "", public_key)

        wrapped_salt = environment_key.get("wrapped_salt")
        decrypted_salt = self.decrypt(wrapped_salt)
        key_digest = CryptoUtils.blake2b_digest(key, decrypted_salt)

        # Determine secret value to be updated -  only update shared value if not overriding or toggling
        if not override and not toggle_override:
            payload_value = encrypted_value
        else:
            payload_value = matching_secret["value"]

        secret_update_payload = {
            "id": matching_secret["id"],
            "key": encrypted_key,
            "keyDigest": key_digest,
            "value": payload_value,
            "tags": matching_secret.get("tags", []), # TODO: Implement tags and comments updates
            "comment": matching_secret.get("comment", ""),
            "path": destination_path if destination_path is not None else matching_secret["path"]
        }

    if toggle_override:
        # Check if the secret has an existing override. If not, raise a custom exception.
        # This prevents toggling an override on a secret that doesn't have one.
        if "override" not in matching_secret or matching_secret["override"] is None:
            raise OverrideNotFoundException(key)
        
        # Retrieve the current override state. If the override is not active, it defaults to False.
        current_override_state = matching_secret["override"].get("is_active", False)
        
        # Prepare the payload to update the override status. The value of the override remains unchanged,
        # but the isActive status is toggled.
        secret_update_payload["override"] = {
            "value": matching_secret["override"]["value"],
            "isActive": not current_override_state  # Toggle the current state.
        }
    elif override:
        # If the override flag is set, check if there is an existing override.
        if matching_secret["override"] is None:
            # If no override exists, create a new override entry.
            # The value for the override is the encrypted value provided by the user,
            # and the override is activated by default.
            secret_update_payload["override"] = {
                "value": encrypted_value,
                "isActive": True
            }
        else:
            # If an override already exists, update its value.
            # If a new value is provided, use it; otherwise, retain the existing override value.
            # The isActive status of the override is also retained from the existing override.
            secret_update_payload["override"] = {
                "value": encrypted_value if value is not None else matching_secret["override"]["value"],
                "isActive": matching_secret["override"].get("is_active", True)
            }

        response = update_phase_secrets(self._token_type, self._app_secret.app_token, env_id, [secret_update_payload], self._api_host)

        if response.status_code == 200:
            return "Success"
        else:
            return f"Error: Failed to update secret. HTTP Status Code: {response.status_code}"


    def delete(self, env_name: str, keys_to_delete: List[str], app_name: str = None, path: str = None) -> List[str]:
        """
        Delete secrets in Phase KMS based on keys and environment, with optional path support.
        
        Args:
            env_name (str): The name (or partial name) of the desired environment.
            keys_to_delete (List[str]): The keys for which to delete the secrets.
            app_name (str, optional): The name of the desired application.
            path (str, optional): The path within which to delete the secrets. If specified, only deletes secrets within this path.
                
        Returns:
            List[str]: A list of keys that were not found and could not be deleted.
        """
        
        user_response = fetch_phase_user(self._token_type, self._app_secret.app_token, self._api_host)
        if user_response.status_code != 200:
            raise ValueError(f"Request failed with status code {user_response.status_code}: {user_response.text}")

        user_data = user_response.json()
        app_name, app_id, env_name, env_id, public_key = phase_get_context(user_data, app_name=app_name, env_name=env_name)

        environment_key = self._find_matching_environment_key(user_data, env_id)
        if environment_key is None:
            raise ValueError(f"No environment found with id: {env_id}")

        wrapped_seed = environment_key.get("wrapped_seed")
        decrypted_seed = self.decrypt(wrapped_seed)
        key_pair = CryptoUtils.env_keypair(decrypted_seed)
        env_private_key = key_pair['privateKey']

        secret_ids_to_delete = []
        keys_not_found = []
        secrets_response = fetch_phase_secrets(self._token_type, self._app_secret.app_token, env_id, self._api_host, path=path)
        secrets_data = secrets_response.json()
            
        for key in keys_to_delete:
            found = False
            for secret in secrets_data:
                if path is not None and secret.get("path", "/") != path:
                    continue  # Skip secrets not in the specified path
                decrypted_key = CryptoUtils.decrypt_asymmetric(secret["key"], env_private_key, public_key)
                if decrypted_key == key:
                    secret_ids_to_delete.append(secret["id"])
                    found = True
                    break
            if not found:
                keys_not_found.append(key)

        if secret_ids_to_delete:
            delete_phase_secrets(self._token_type, self._app_secret.app_token, env_id, secret_ids_to_delete, self._api_host)
            
        return keys_not_found
    

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
