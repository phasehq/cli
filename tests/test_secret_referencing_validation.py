import pytest
from phase_cli.utils.secret_referencing import _parse_reference_context


def test_cross_app_reference_without_env_raises_error():
    ref = "backend_api::SECRET_KEY"
    current_app = "my_app"
    current_env = "dev"

    with pytest.raises(
        ValueError, match="Cross-application references must specify an environment"
    ):
        _parse_reference_context(ref, current_app, current_env)


def test_cross_app_reference_with_env_is_valid():
    ref = "backend_api::production.SECRET_KEY"
    current_app = "my_app"
    current_env = "dev"

    app, env, path, key = _parse_reference_context(ref, current_app, current_env)
    assert app == "backend_api"
    assert env == "production"
    assert key == "SECRET_KEY"


def test_local_reference_is_valid():
    ref = "SECRET_KEY"
    current_app = "my_app"
    current_env = "dev"

    app, env, path, key = _parse_reference_context(ref, current_app, current_env)
    assert app == "my_app"
    assert env == "dev"
    assert key == "SECRET_KEY"


def test_cross_env_reference_is_valid():
    ref = "production.SECRET_KEY"
    current_app = "my_app"
    current_env = "dev"

    app, env, path, key = _parse_reference_context(ref, current_app, current_env)
    assert app == "my_app"
    assert env == "production"
    assert key == "SECRET_KEY"


def test_cross_app_reference_with_empty_env_raises_error():
    ref = "backend_api::.SECRET_KEY"
    current_app = "my_app"
    current_env = "dev"

    with pytest.raises(
        ValueError, match="Cross-application references must specify an environment"
    ):
        _parse_reference_context(ref, current_app, current_env)
