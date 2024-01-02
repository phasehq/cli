from phase_cli.utils.phase_io import Phase
from phase_cli.utils.misc import render_table
from rich.console import Console

def phase_list_secrets(show=False, env_name=None, phase_app=None, tags=None):
    """
    Lists the secrets fetched from Phase for the specified environment, optionally filtered by tags.

    Args:
        show (bool, optional): Whether to show the decrypted secrets. Defaults to False.
        env_name (str, optional): The name of the environment from which secrets are fetched. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.
        tags (str, optional): The tag or comma-separated list of tags to filter the secrets. Defaults to None.

    Raises:
        ValueError: If the returned secrets data from Phase is not in the expected list format.
    """
    # Initialize the Phase class
    phase = Phase()
    console = Console()

    try:
        secrets_data = phase.get(env_name=env_name, app_name=phase_app, tag=tags)
        
        # Check that secrets_data is a list of dictionaries
        if not isinstance(secrets_data, list):
            raise ValueError("Unexpected format: secrets data is not a list")

        # Render the table
        render_table(secrets_data, show=show)

        if not show:
            print("🥽 To uncover the secrets, use: phase secrets list --show")
            print ("🔬 To view a secret, use: phase secrets get <key>\n")

    except ValueError as e:
        console.log(f"Error: {e}")
