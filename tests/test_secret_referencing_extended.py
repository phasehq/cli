import pytest
import phase_cli.utils.secret_referencing as sr
from phase_cli.utils.secret_referencing import resolve_secret_reference, resolve_all_secrets, EnvironmentNotFoundException


class MockPhase:
    def get(self, env_name, app_name, keys, path):
        # Cross-app: other_app dev root
        if app_name == "other_app" and env_name == "dev" and path == "/":
            return [
                {"key": "API_KEY", "value": "other_app_api_key"},
                {"key": "POSTGRESQL_USER", "value": "pg_user"},
                {"key": "POSTGRESQL_PASSWORD", "value": "pg_password"},
                {"key": "POSTGRESQL_DB", "value": "db"},
                {"key": "POSTGRESQL_HOST", "value": "localhost"},
                {"key": "POSTGRESQL_URL", "value": "postgresql://${/creds/POSTGRESQL_USER}:${/creds/POSTGRESQL_PASSWORD}@${POSTGRESQL_HOST}/${POSTGRESQL_DB}"},
                # Cycle keys
                {"key": "A", "value": "${B}"},
                {"key": "B", "value": "${C}"},
                {"key": "C", "value": "${A}"},
            ]
        # Cross-app: other_app dev creds path
        if app_name == "other_app" and env_name == "dev" and path == "/creds":
            return [
                {"key": "POSTGRESQL_USER", "value": "pg_user"},
                {"key": "POSTGRESQL_PASSWORD", "value": "pg_password"},
            ]
        # Cross-app: other_app prod config path
        if app_name == "other_app" and env_name == "prod" and path == "/config":
            return [{"key": "DB_PASSWORD", "value": "other_app_db_password"}]
        # Cross-app: backend_api production frontend path
        if app_name == "backend_api" and env_name == "production" and path == "/frontend":
            return [{"key": "SECRET_KEY", "value": "backend_api_secret_key"}]
        # Regular env reference example
        if env_name == "prod" and path == "/frontend":
            return [{"key": "SECRET_KEY", "value": "prod_secret_value"}]
        raise EnvironmentNotFoundException(env_name=env_name)


@pytest.fixture
def phase():
    return MockPhase()


@pytest.fixture
def current_env_name():
    return "current"


@pytest.fixture
def current_application_name():
    return "test_app"


@pytest.fixture(autouse=True)
def clear_cache():
    sr._SECRETS_CACHE.clear()


def test_partial_env_case_insensitive_variants(phase, current_application_name, current_env_name):
    value = "X=${development.DEBUG};Y=${DEV.DEBUG};Z=${DeVeLoPmEnT.DEBUG}"
    all_secrets = [
        {"environment": "Development", "path": "/", "key": "DEBUG", "value": "true"},
    ]
    resolved_value = resolve_all_secrets(value, all_secrets, phase, current_application_name, current_env_name)
    assert resolved_value == "X=true;Y=true;Z=true"


def test_partial_env_substring_variants(phase, current_application_name, current_env_name):
    value = "A=${deve.DEBUG};B=${lop.DEBUG}"
    all_secrets = [
        {"environment": "Development", "path": "/", "key": "DEBUG", "value": "on"},
    ]
    resolved_value = resolve_all_secrets(value, all_secrets, phase, current_application_name, current_env_name)
    assert resolved_value == "A=on;B=on"


def test_partial_env_ambiguous_prefers_shortest(phase, current_application_name, current_env_name):
    value = "Z=${de.DEBUG}"
    all_secrets = [
        {"environment": "dev", "path": "/", "key": "DEBUG", "value": "a"},
        {"environment": "development", "path": "/", "key": "DEBUG", "value": "b"},
    ]
    resolved_value = resolve_all_secrets(value, all_secrets, phase, current_application_name, current_env_name)
    assert resolved_value == "Z=a"


def test_ambiguous_exact_wins(phase, current_application_name, current_env_name):
    value = "Z=${dev.DEBUG}"
    all_secrets = [
        {"environment": "dev", "path": "/", "key": "DEBUG", "value": "a"},
        {"environment": "development", "path": "/", "key": "DEBUG", "value": "b"},
    ]
    resolved_value = resolve_all_secrets(value, all_secrets, phase, current_application_name, current_env_name)
    assert resolved_value == "Z=a"


def test_recursive_local_multi_layer(phase, current_application_name, current_env_name):
    value = "CONN=${/db/URL}"
    all_secrets = [
        {"environment": current_env_name, "path": "/db", "key": "USER", "value": "u"},
        {"environment": current_env_name, "path": "/db", "key": "PASS", "value": "p"},
        {"environment": current_env_name, "path": "/db", "key": "HOST", "value": "h"},
        {"environment": current_env_name, "path": "/db", "key": "DB", "value": "d"},
        {"environment": current_env_name, "path": "/db", "key": "URL", "value": "postgresql://${/db/USER}:${/db/PASS}@${/db/HOST}/${/db/DB}"},
    ]
    resolved_value = resolve_all_secrets(value, all_secrets, phase, current_application_name, current_env_name)
    assert resolved_value == "CONN=postgresql://u:p@h/d"


def test_recursive_missing_inner_reference(phase, current_application_name, current_env_name):
    value = "CONN=${/db/URL}"
    all_secrets = [
        {"environment": current_env_name, "path": "/db", "key": "USER", "value": "u"},
        {"environment": current_env_name, "path": "/db", "key": "PASS", "value": "p"},
        {"environment": current_env_name, "path": "/db", "key": "URL", "value": "postgresql://${/db/USER}:${/db/PASS}@${/db/HOST}/${/db/DB}"},
    ]
    resolved_value = resolve_all_secrets(value, all_secrets, phase, current_application_name, current_env_name)
    assert "${/db/HOST}" in resolved_value and "${/db/DB}" in resolved_value


def test_cycle_self_reference_cross_app(phase, current_application_name, current_env_name):
    value = "X=${other_app::dev.A}"
    all_secrets = []
    resolved_value = resolve_all_secrets(value, all_secrets, phase, current_application_name, current_env_name)
    assert resolved_value.startswith("X=${")
    assert "A" in resolved_value


def test_cycle_multi_secret_loop_cross_app(phase, current_application_name, current_env_name):
    value = "X=${other_app::dev.A} Y=${other_app::dev.B} Z=${other_app::dev.C}"
    all_secrets = []
    resolved_value = resolve_all_secrets(value, all_secrets, phase, current_application_name, current_env_name)
    assert "${" in resolved_value  # at least one unresolved placeholder due to cycle


def test_cycle_across_env_case_variants_local(phase, current_application_name, current_env_name):
    value = "X=${Development.DEBUG}"
    all_secrets = [
        {"environment": "Development", "path": "/", "key": "DEBUG", "value": "${development.DEBUG}"},
        {"environment": "development", "path": "/", "key": "DEBUG", "value": "${Development.DEBUG}"},
    ]
    resolved_value = resolve_all_secrets(value, all_secrets, phase, current_application_name, current_env_name)
    assert resolved_value == "X=${Development.DEBUG}" or resolved_value == "X=${development.DEBUG}"


def test_multiple_occurrences_same_reference(phase, current_application_name, current_env_name):
    value = "A=${KEY};B=${KEY}"
    all_secrets = [
        {"environment": current_env_name, "path": "/", "key": "KEY", "value": "v"},
    ]
    resolved_value = resolve_all_secrets(value, all_secrets, phase, current_application_name, current_env_name)
    assert resolved_value == "A=v;B=v"


