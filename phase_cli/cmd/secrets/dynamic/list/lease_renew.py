import sys
from rich.console import Console
from phase_cli.utils.phase_io import Phase
from phase_cli.utils.network import renew_dynamic_secret_lease


def phase_dynamic_secrets_lease_renew(lease_id, ttl, env_name=None, phase_app=None, phase_app_id=None):
    """
    Renew a dynamic secret lease by lease_id with a given TTL (seconds).
    """
    console = Console()
    try:
        phase = Phase()
        user_data = phase.init()
        from phase_cli.utils.misc import phase_get_context
        app_name, app_id, resolved_env_name, env_id, _ = phase_get_context(user_data, app_name=phase_app, env_name=env_name, app_id=phase_app_id)

        response = renew_dynamic_secret_lease(
            phase._token_type,
            phase._app_secret.app_token,
            phase._api_host,
            app_id,
            resolved_env_name,
            lease_id,
            int(ttl),
        )

        if sys.stdout.isatty():
            try:
                console.print_json(data=response.json())
            except Exception:
                console.print(response.text)
        else:
            try:
                import json
                console.print(json.dumps(response.json(), indent=4))
            except Exception:
                console.print(response.text)
    except Exception as e:
        console.log(f"Error: {e}")
        sys.exit(1)


