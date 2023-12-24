import sys
import re
from phase_cli.utils.phase_io import Phase
from phase_cli.utils.const import cross_env_pattern, local_ref_pattern

def phase_secrets_env_export(env_name=None, phase_app=None, keys=None, tags=None):
    """
    Decrypts and exports secrets to a plain text .env format based on the provided environment and keys. 
    The function also resolves any references to other secrets, whether they are within the same environment 
    (local references) or from a different environment (cross-environment references). Local references 
    are indicated using the pattern `${KEY_NAME}`, while cross-environment references use the pattern 
    `${ENV_NAME.KEY_NAME}`.

    Args:
        env_name (str, optional): The name of the environment from which secrets are fetched. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.
        keys (list, optional): List of keys for which to fetch the secrets. If None, fetches all secrets. Defaults to None.
    """

    # Initialize the Phase class
    phase = Phase()
    console = Console()

    try:
        secrets = phase.get(env_name=env_name, keys=keys, app_name=phase_app, tag=tags)

        # Create a dictionary from the fetched secrets for easy look-up
        secrets_dict = {secret["key"]: secret["value"] for secret in secrets}

        # Iterate through the secrets and resolve references
        for key, value in secrets_dict.items():

            # Resolve cross environment references
            cross_env_matches = re.findall(cross_env_pattern, value)
            for ref_env, ref_key in cross_env_matches:
                try:
                    ref_secret = phase.get(env_name=ref_env, keys=[ref_key], app_name=phase_app)[0]
                    value = value.replace(f"${{{ref_env}.{ref_key}}}", ref_secret['value'])
                except ValueError as e:
                    print(f"# Warning: The environment '{ref_env}' for key '{key}' either does not exist or you do not have access to it.")

            # Resolve local references
            local_ref_matches = re.findall(local_ref_pattern, value)
            for ref_key in local_ref_matches:
                value = value.replace(f"${{{ref_key}}}", secrets_dict.get(ref_key, ""))
            
            # Print the key-value pair
            print(f'{key}="{value}"')

    except ValueError as e:
        console.log(f"Error: {e}")
