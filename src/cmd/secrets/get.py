from src.utils.phase_io import Phase
from src.utils.misc import render_table

def phase_secrets_get(key, env_name=None, phase_app=None):
    """
    Fetch and print a single secret based on a given key.
    
    :param key: The key associated with the secret to fetch.
    :param env_name: The name of the environment, if any. Defaults to None.
    """

    # Initialize the Phase class
    phase = Phase()
    
    try:
        key = key.upper()
        # Here we wrap the key in a list since the get method now expects a list of keys
        secrets_data = phase.get(env_name=env_name, keys=[key], app_name=phase_app)
        
        # Find the specific secret for the given key
        secret_data = next((secret for secret in secrets_data if secret["key"] == key), None)
        
        # Check that secret_data was found and is a dictionary
        if not secret_data:
            print("🔍 Secret not found...")
            return
        if not isinstance(secret_data, dict):
            raise ValueError("Unexpected format: secret data is not a dictionary")
        
        # Print the secret data in a table-like format
        render_table([secret_data], show=True)

    except ValueError as e:
        print(e)