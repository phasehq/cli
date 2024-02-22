import pytest
from phase_cli.utils.secret_referencing import resolve_secret_reference, resolve_all_secrets

class MockPhase:
    def get(self, env_name, app_name, path, keys):
        mock_responses = {
            ('current_env', '/', tuple(['SECRET_KEY'])): [{'value': 'prod_secret_value'}],
            ('dev', '/', tuple(['DEBUG'])): [{'value': 'dev_debug_value'}],
            ('prod', '/frontend/', tuple(['SECRET_KEY'])): [{'value': 'frontend_secret_value'}],
            ('current_env', '/backend/payments/', tuple(['STRIPE_KEY'])): [{'value': 'stripe_key_value'}],
            ('staging', '/', tuple(['API_KEY'])): [{'value': 'staging_api_key'}],
            ('prod', '/api/', tuple(['DATABASE_URL'])): [{'value': 'database_prod_url'}],
            ('test', '/', tuple(['TEST_API_KEY'])): [{'value': 'test_api_key_value'}],
            ('dev', '/services/', tuple(['SERVICE_KEY'])): [{'value': 'service_dev_key'}],
            ('prod', '/services/email/', tuple(['EMAIL_SERVICE_KEY'])): [{'value': 'email_service_prod_key'}],
            ('current_env', '/config/', tuple(['CONFIG_KEY'])): [{'value': 'config_key_value'}],
            ('dev', '/', tuple(['LOGGER_LEVEL'])): [{'value': 'debug'}],
            ('prod', '/db/', tuple(['DB_PASSWORD'])): [{'value': 'db_prod_password'}],
            ('staging', '/db/', tuple(['DB_USER'])): [{'value': 'db_staging_user'}],
            ('current_env', '/', tuple(['ENV_VAR'])): [{'value': 'env_var_value'}],
            ('dev', '/temp/', tuple(['TEMP_KEY'])): [{'value': 'temp_dev_key'}],
            ('prod', '/secure/', tuple(['SECURE_KEY'])): [{'value': 'secure_prod_key'}],
            ('staging', '/files/', tuple(['FILE_ACCESS_KEY'])): [{'value': 'file_access_staging_key'}],
            ('test', '/config/', tuple(['TEST_CONFIG'])): [{'value': 'test_config_value'}],
            ('dev', '/api_keys/', tuple(['DEV_API_KEY'])): [{'value': 'dev_api_key_value'}],
            ('prod', '/api_keys/', tuple(['PROD_API_KEY'])): [{'value': 'prod_api_key_value'}],
            ('staging', '/', tuple(['STAGING_SECRET'])): [{'value': 'staging_secret_value'}],
            ('current_env', '/payments/', tuple(['PAYMENT_PROCESSOR_KEY'])): [{'value': 'payment_processor_key_value'}],
            ('dev', '/debug/', tuple(['DEBUG_FLAG'])): [{'value': 'true'}],
            ('prod', '/features/', tuple(['FEATURE_FLAG'])): [{'value': 'enabled'}],
            ('staging', '/features/', tuple(['STAGING_FEATURE_FLAG'])): [{'value': 'disabled'}],
        }
        response_key = (env_name, path, tuple(keys))
        return mock_responses.get(response_key, [])


# Format - key, current environment, value
@pytest.mark.parametrize("ref,current_env_name,expected", [
    ("SECRET_KEY", "current_env", "prod_secret_value"),
    ("dev.DEBUG", "current_env", "dev_debug_value"),
    ("prod./frontend/SECRET_KEY", "prod", "frontend_secret_value"),
    ("/backend/payments/STRIPE_KEY", "current_env", "stripe_key_value"),
    ("API_KEY", "staging", "staging_api_key"),
    ("prod./api/DATABASE_URL", "prod", "database_prod_url"),
    ("test.TEST_API_KEY", "test", "test_api_key_value"),
    ("dev./services/SERVICE_KEY", "dev", "service_dev_key"),
    ("prod./services/email/EMAIL_SERVICE_KEY", "prod", "email_service_prod_key"),

])

def test_resolve_secret_reference(ref, current_env_name, expected, mocker):
    phase = MockPhase()
    mocker.patch.object(phase, 'get', wraps=phase.get)
    resolved_value = resolve_secret_reference(ref, current_env_name, phase)
    assert resolved_value == expected

def test_resolve_all_secrets(mocker):
    phase = MockPhase()
    mocker.patch.object(phase, 'get', wraps=phase.get)
    value = "Some secrets: ${SECRET_KEY}, ${dev.DEBUG}, ${prod./frontend/SECRET_KEY}, ${/backend/payments/STRIPE_KEY}"
    expected = "Some secrets: prod_secret_value, dev_debug_value, frontend_secret_value, stripe_key_value"
    current_env_name = "current_env"
    resolved_value = resolve_all_secrets(value, current_env_name, phase)
    assert resolved_value == expected

def test_resolve_secret_reference_missing_secret(mocker):
    phase = MockPhase()
    mocker.patch.object(phase, 'get', wraps=phase.get)
    with pytest.raises(ValueError) as excinfo:
        resolve_secret_reference("missing.SECRET", "current_env", phase)
    assert "Secret 'SECRET' not found in environment 'missing', path '/'." in str(excinfo.value)

def test_resolve_all_secrets_with_missing_secret(mocker):
    phase = MockPhase()
    mocker.patch.object(phase, 'get', wraps=phase.get)
    value = "A string with a ${missing.SECRET} reference."
    current_env_name = "current_env"
    with pytest.raises(ValueError) as excinfo:
        resolve_all_secrets(value, current_env_name, phase)
    assert "Secret 'SECRET' not found in environment 'missing', path '/'." in str(excinfo.value)
