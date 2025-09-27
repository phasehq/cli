import sys
from rich.console import Console
from phase_cli.utils.phase_io import Phase
from phase_cli.utils.network import list_dynamic_secrets


def phase_dynamic_secrets_list(env_name=None, phase_app=None, phase_app_id=None, path='/'):
    """
    List dynamic secrets (metadata only) for the app/env/path.
    Uses phase.get(dynamic=True, lease=False) and prints highlighted JSON if TTY.
    """
    console = Console()
    try:
        phase = Phase()
        user_data = phase.init()
        from phase_cli.utils.misc import phase_get_context
        app_name, app_id, resolved_env_name, env_id, _ = phase_get_context(user_data, app_name=phase_app, env_name=env_name, app_id=phase_app_id)

        response = list_dynamic_secrets(
            phase._token_type,
            phase._app_secret.app_token,
            phase._api_host,
            app_id,
            resolved_env_name,
            path,
        )
        dynamic_only = response.json()

        if sys.stdout.isatty():
            console.print_json(data=dynamic_only)
        else:
            import json
            console.print_json(json.dumps(dynamic_only, indent=4))
    except Exception as e:
        console.log(f"Error: {e}")
        sys.exit(1)


