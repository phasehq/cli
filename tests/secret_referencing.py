import pytest
from unittest.mock import Mock, patch
import phase_cli.utils.secret_referencing as sr
from phase_cli.utils.secret_referencing import resolve_secret_reference, resolve_all_secrets, EnvironmentNotFoundException
from phase_cli.utils.const import SECRET_REF_REGEX

# Mock data for secrets
secrets_dict = {
    "current": {
        "/": {
            "KEY": "value1"
        },
        "/backend/payments": {
            "STRIPE_KEY": "stripe_value"
        }
    },
    "staging": {
        "/": {
            "DEBUG": "staging_debug_value"
        }
    },
    "prod": {
        "/frontend": {
            "SECRET_KEY": "prod_secret_value"
        }
    }
}

# Mock Phase class
class MockPhase:
    def get(self, env_name, app_name, keys, path):
        # Handle cross-application references
        if app_name == "other_app" and env_name == "dev" and path == "/":
            return [
                {"key": "API_KEY", "value": "other_app_api_key"},
                {"key": "POSTGRESQL_USER", "value": "pg_user"},
                {"key": "POSTGRESQL_PASSWORD", "value": "pg_password"},
                {"key": "POSTGRESQL_DB", "value": "db"},
                {"key": "POSTGRESQL_HOST", "value": "localhost"},
                {"key": "POSTGRESQL_URL", "value": "postgresql://${/creds/POSTGRESQL_USER}:${/creds/POSTGRESQL_PASSWORD}@${POSTGRESQL_HOST}/${POSTGRESQL_DB}"},
                {"key": "A", "value": "${B}"},
                {"key": "B", "value": "${C}"},
                {"key": "C", "value": "${A}"},
            ]
        elif app_name == "other_app" and env_name == "dev" and path == "/creds":
            return [
                {"key": "POSTGRESQL_USER", "value": "pg_user"},
                {"key": "POSTGRESQL_PASSWORD", "value": "pg_password"},
            ]
        elif app_name == "other_app" and env_name == "prod" and path == "/config":
            return [{"key": "DB_PASSWORD", "value": "other_app_db_password"}]
        elif app_name == "backend_api" and env_name == "production" and path == "/frontend":
            return [{"key": "SECRET_KEY", "value": "backend_api_secret_key"}]
        # Handle regular environment references
        elif env_name == "prod" and path == "/frontend":
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

def test_resolve_local_reference_root(phase, current_application_name, current_env_name):
    ref = "KEY"
    resolved_value = resolve_secret_reference(ref, secrets_dict, phase, current_application_name, current_env_name)
    assert resolved_value == "value1"

def test_resolve_local_reference_path(phase, current_application_name, current_env_name):
    ref = "/backend/payments/STRIPE_KEY"
    resolved_value = resolve_secret_reference(ref, secrets_dict, phase, current_application_name, current_env_name)
    assert resolved_value == "stripe_value"

def test_resolve_cross_environment_root(phase, current_application_name, current_env_name):
    ref = "staging.DEBUG"
    resolved_value = resolve_secret_reference(ref, secrets_dict, phase, current_application_name, current_env_name)
    assert resolved_value == "staging_debug_value"

def test_resolve_cross_environment_path(phase, current_application_name, current_env_name):
    ref = "prod./frontend/SECRET_KEY"
    resolved_value = resolve_secret_reference(ref, secrets_dict, phase, current_application_name, current_env_name)
    assert resolved_value == "prod_secret_value"

def test_resolve_all_secrets(phase, current_application_name, current_env_name):
    value = "Use this key: ${KEY}, and this staging key: ${staging.DEBUG}, and this path key: ${/backend/payments/STRIPE_KEY}"
    all_secrets = [
        {"environment": "current", "path": "/", "key": "KEY", "value": "value1"},
        {"environment": "staging", "path": "/", "key": "DEBUG", "value": "staging_debug_value"},
        {"environment": "current", "path": "/backend/payments", "key": "STRIPE_KEY", "value": "stripe_value"}
    ]
    resolved_value = resolve_all_secrets(value, all_secrets, phase, current_application_name, current_env_name)
    expected_value = "Use this key: value1, and this staging key: staging_debug_value, and this path key: stripe_value"
    assert resolved_value == expected_value

# Edge Case: Missing key in the current environment
def test_resolve_missing_local_key(phase, current_application_name, current_env_name):
    ref = "MISSING_KEY"
    resolved_value = resolve_secret_reference(ref, secrets_dict, phase, current_application_name, current_env_name)
    assert resolved_value == "${MISSING_KEY}"

# Edge Case: Missing key in a cross environment reference
def test_resolve_missing_cross_env_key(phase, current_application_name, current_env_name):
    ref = "prod.MISSING_KEY"
    resolved_value = resolve_secret_reference(ref, secrets_dict, phase, current_application_name, current_env_name)
    assert resolved_value == "${prod.MISSING_KEY}"

# Edge Case: Missing path in a cross environment reference
def test_resolve_missing_cross_env_path(phase, current_application_name, current_env_name):
    ref = "prod./missing_path/SECRET_KEY"
    resolved_value = resolve_secret_reference(ref, secrets_dict, phase, current_application_name, current_env_name)
    assert resolved_value == "${prod./missing_path/SECRET_KEY}"

# Complex Case: Mixed references with missing values
def test_resolve_mixed_references_with_missing(phase, current_application_name, current_env_name):
    value = "Local: ${KEY}, Missing Local: ${MISSING_KEY}, Cross: ${staging.DEBUG}, Missing Cross: ${prod.MISSING_KEY}"
    all_secrets = [
        {"environment": "current", "path": "/", "key": "KEY", "value": "value1"},
        {"environment": "staging", "path": "/", "key": "DEBUG", "value": "staging_debug_value"}
    ]
    resolved_value = resolve_all_secrets(value, all_secrets, phase, current_application_name, current_env_name)
    expected_value = "Local: value1, Missing Local: ${MISSING_KEY}, Cross: staging_debug_value, Missing Cross: ${prod.MISSING_KEY}"
    assert resolved_value == expected_value

# Edge Case: Local reference with missing path
def test_resolve_local_reference_missing_path(phase, current_application_name, current_env_name):
    ref = "/missing_path/KEY"
    resolved_value = resolve_secret_reference(ref, secrets_dict, phase, current_application_name, current_env_name)
    assert resolved_value == "${/missing_path/KEY}"

# Edge Case: Invalid reference format
def test_resolve_invalid_reference_format(phase, current_application_name, current_env_name):
    ref = "invalid_format"
    resolved_value = resolve_secret_reference(ref, secrets_dict, phase, current_application_name, current_env_name)
    assert resolved_value == "${invalid_format}"

# Cross Application: Basic root path reference
def test_resolve_cross_application_root(phase, current_application_name, current_env_name):
    ref = "other_app::dev.API_KEY"
    resolved_value = resolve_secret_reference(ref, secrets_dict, phase, current_application_name, current_env_name)
    assert resolved_value == "other_app_api_key"

# Cross Application: Reference with specific path
def test_resolve_cross_application_path(phase, current_application_name, current_env_name):
    ref = "other_app::prod./config/DB_PASSWORD"
    resolved_value = resolve_secret_reference(ref, secrets_dict, phase, current_application_name, current_env_name)
    assert resolved_value == "other_app_db_password"

# Cross Application: Missing key
def test_resolve_cross_application_missing_key(phase, current_application_name, current_env_name):
    ref = "other_app::dev.MISSING_KEY"
    resolved_value = resolve_secret_reference(ref, secrets_dict, phase, current_application_name, current_env_name)
    assert resolved_value == "${other_app::dev.MISSING_KEY}"

# Cross Application: Missing environment
def test_resolve_cross_application_missing_env(phase, current_application_name, current_env_name):
    ref = "other_app::missing_env.API_KEY"
    resolved_value = resolve_secret_reference(ref, secrets_dict, phase, current_application_name, current_env_name)
    assert resolved_value == "${other_app::missing_env.API_KEY}"

# Cross Application: Mixed references with cross-application
def test_resolve_mixed_references_with_cross_app(phase, current_application_name, current_env_name):
    value = "Local: ${KEY}, Cross Env: ${staging.DEBUG}, Cross App: ${other_app::dev.API_KEY}, Missing Cross App: ${other_app::dev.MISSING_KEY}"
    all_secrets = [
        {"environment": "current", "path": "/", "key": "KEY", "value": "value1"},
        {"environment": "staging", "path": "/", "key": "DEBUG", "value": "staging_debug_value"}
    ]
    resolved_value = resolve_all_secrets(value, all_secrets, phase, current_application_name, current_env_name)
    expected_value = "Local: value1, Cross Env: staging_debug_value, Cross App: other_app_api_key, Missing Cross App: ${other_app::dev.MISSING_KEY}"
    assert resolved_value == expected_value

# Cross Application: Complex example with frontend path
def test_resolve_cross_app_frontend_example(phase, current_application_name, current_env_name):
    ref = "backend_api::production./frontend/SECRET_KEY"
    resolved_value = resolve_secret_reference(ref, secrets_dict, phase, current_application_name, current_env_name)
    assert resolved_value == "backend_api_secret_key"


def test_recursive_cross_app_resolution(phase, current_application_name, current_env_name):
    # App A value referencing App B value which itself contains references
    value = "DB=${other_app::dev.POSTGRESQL_URL}"
    all_secrets = [
        {"environment": current_env_name, "path": "/", "key": "POSTGRESQL_URL", "value": "postgresql://${other_app::dev.POSTGRESQL_USER}:${other_app::dev.POSTGRESQL_PASSWORD}@${other_app::dev.POSTGRESQL_HOST}/${other_app::dev.POSTGRESQL_DB}"}
    ]
    resolved_value = resolve_all_secrets(value, all_secrets, phase, current_application_name, current_env_name)
    assert resolved_value == "DB=postgresql://pg_user:pg_password@localhost/db"


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
