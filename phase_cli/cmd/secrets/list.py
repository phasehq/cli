from phase_cli.utils.phase_io import Phase
from phase_cli.utils.misc import render_table

def phase_list_secrets(show=False, env_name=None, phase_app=None):
    """
    Lists the secrets fetched from Phase for the specified environment.

    Args:
        show (bool, optional): Whether to show the decrypted secrets. Defaults to False.
        env_name (str, optional): The name of the environment from which secrets are fetched. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.

    Raises:
        ValueError: If the returned secrets data from Phase is not in the expected list format.
    """
    # Initialize the Phase class
    phase = Phase()

    try:
        secrets_data = phase.get(env_name=env_name, app_name=phase_app)
        
        # Check that secrets_data is a list of dictionaries
        if not isinstance(secrets_data, list):
            raise ValueError("Unexpected format: secrets data is not a list")

        # Render the table
        render_table(secrets_data, show=show)

        if not show:
            print("\n🥽 To uncover the secrets, use: phase secrets list --show")

    except ValueError as e:
        print(f"⚠️  Warning: The environment '{env_name}' either does not exist or you do not have access to it.")
