import sys
import json
from rich.console import Console
from phase_cli.utils.phase_io import Phase
from phase_cli.utils.network import create_dynamic_secret_lease


def phase_dynamic_secrets_lease_generate(secret_id, env_name=None, phase_app=None, phase_app_id=None, ttl=None):
    """
    Generate a dynamic secret lease and credentials for a given secret_id.
    Optionally pass a TTL (seconds) to override the default TTL.
    """
    console = Console()
    try:
        phase = Phase()
        user_data = phase.init()
        from phase_cli.utils.misc import phase_get_context
        app_name, app_id, resolved_env_name, env_id, _ = phase_get_context(user_data, app_name=phase_app, env_name=env_name, app_id=phase_app_id)

        response = create_dynamic_secret_lease(
            phase._token_type,
            phase._app_secret.app_token,
            phase._api_host,
            app_id,
            resolved_env_name,
            secret_id,
            int(ttl) if ttl is not None else None,
        )

        if sys.stdout.isatty():
            try:
                console.print_json(data=response.json())
            except Exception:
                console.print(response.text)
        else:
            try:
                print(json.dumps(response.json(), indent=4))
            except Exception:
                print(response.text)
    except Exception as e:
        console.log(f"Error: {e}")
        sys.exit(1)
