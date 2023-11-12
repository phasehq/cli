import sys
import re
import base64
from src.utils.phase_io import Phase
from src.utils.const import cross_env_pattern, local_ref_pattern

def phase_secrets_env_export(phase_service_token=None, phase_service_host=None, env_name=None, phase_app=None, keys=None, export_type='plain'):
    """
    Decrypts and exports secrets to a specified format based on the provided environment and keys. 
    The function also resolves any references to other secrets, whether they are within the same environment 
    (local references) or from a different environment (cross-environment references).

    Args:
        phase_service_token (str): The service token for authentication.
        phase_service_host (str): The Phase service host URL.
        env_name (str, optional): The name of the environment from which secrets are fetched.
        phase_app (str, optional): The name of the Phase application.
        keys (list, optional): List of keys for which to fetch the secrets.
        export_type (str, optional): The export type, either 'plain' for .env format or 'k8' for Kubernetes format.
    """

    phase = Phase(init=False, pss=phase_service_token, host=phase_service_host)

    try:
        secrets = phase.get(env_name=env_name, keys=keys, app_name=phase_app)
    except ValueError as e:
        print(f"Failed to fetch secrets: The environment '{env_name}' either does not exist or you do not have access to it.")
        sys.exit(1)

    secrets_dict = {secret["key"]: secret["value"] for secret in secrets}

    for key, value in secrets_dict.items():
        cross_env_matches = re.findall(cross_env_pattern, value)
        for ref_env, ref_key in cross_env_matches:
            try:
                ref_secret = phase.get(env_name=ref_env, keys=[ref_key], app_name=phase_app)[0]
                resolved_value = ref_secret['value']
                if export_type == 'k8':
                    resolved_value = base64.b64encode(resolved_value.encode()).decode()
                value = value.replace(f"${{{ref_env}.{ref_key}}}", resolved_value)
            except ValueError as e:
                print(f"# Warning: The environment '{ref_env}' for key '{key}' either does not exist or you do not have access to it.")

        local_ref_matches = re.findall(local_ref_pattern, value)
        for ref_key in local_ref_matches:
            resolved_value = secrets_dict.get(ref_key, "")
            if export_type == 'k8':
                resolved_value = base64.b64encode(resolved_value.encode()).decode()
            value = value.replace(f"${{{ref_key}}}", resolved_value)

        # Encode values if Kubernetes format is selected
        if export_type == 'k8':
            secrets_dict[key] = base64.b64encode(value.encode()).decode()
        else:
            secrets_dict[key] = value

    # Return the dictionary for Kubernetes, or print for .env
    if export_type == 'k8':
        return secrets_dict
    else:
        for key, value in secrets_dict.items():
            print(f'{key}="{value}"')