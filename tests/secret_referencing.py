import pytest
from unittest.mock import Mock, patch
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
            return [{"key": "API_KEY", "value": "other_app_api_key"}]
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
