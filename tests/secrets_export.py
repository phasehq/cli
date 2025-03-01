import pytest
import json
import yaml
import csv
import io
import toml
import sys
from xml.etree import ElementTree as ET
from configparser import ConfigParser
import hcl2
from unittest.mock import Mock, patch
from phase_cli.cmd.secrets.export import (
    export_json, export_csv, export_yaml, export_toml, export_xml,
    export_dotenv, export_hcl, export_ini, export_java_properties, export_kv, phase_secrets_env_export,
)

secrets_dict = {
    'AWS_SECRET_ACCESS_KEY': 'aCRAMarEbFC3Q5c24pi7AVMIt6TaCfHeFZ4KCf/a',
    'AWS_ACCESS_KEY_ID': 'AKIAIX4ONRSG6ODEFVJA',
    'JWT_SECRET': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNjMzNjIwMTcxLCJleHAiOjIyMDg5ODUyMDB9.pHnckabbMbwTHAJOkb5Z7G7B4chY6GllJf6K2m96z3A',
    'STRIPE_SECRET_KEY': 'sk_test_EeHnL644i6zo4Iyq4v1KdV9H', 
    'DJANGO_SECRET_KEY': 'wwf*2#86t64!fgh6yav$aoeuo@u2o@fy&*gg76q!&%6x_wbduad',
    'DJANGO_DEBUG': 'True', 
    'POSTGRES_CONNECTION_STRING': 'postgresql://postgres:6c37810ec6e74ec3228416d2844564fceb99ebd94b29f4334c244db011630b0e@mc-laren-prod-db.c9ufzjtplsaq.us-west-1.rds.amazonaws.com:5432/XP1_LM', 
    'DB_HOST': 'mc-laren-prod-db.c9ufzjtplsaq.us-west-1.rds.amazonaws.com', 
    'DB_USER': 'postgres', 
    'DB_NAME': 'XP1_LM', 
    'DB_PASSWORD': '6c37810ec6e74ec3228416d2844564fceb99ebd94b29f4334c244db011630b0e', 
    'DB_PORT': '5432'
}


@patch('phase_cli.cmd.secrets.export.Phase')
def test_phase_secrets_env_export_specific_keys(mock_phase, capsys):
    mock_phase_instance = mock_phase.return_value
    # Include a 'path' key with a dummy value for each secret
    all_secrets = [{'key': k, 'value': v, 'environment': 'development', 'application': 'test-application-name', 'path': 'dummy/path'} for k, v in secrets_dict.items()]
    mock_phase_instance.get.return_value = all_secrets

    # Call phase_secrets_env_export with specific keys
    selected_keys = ['AWS_SECRET_ACCESS_KEY', 'AWS_ACCESS_KEY_ID']
    phase_secrets_env_export(keys=selected_keys)

    # Capture the output
    captured = capsys.readouterr().out

    # Process the output by splitting and removing double quotes
    exported_secrets = {line.split('=')[0]: line.split('=')[1].strip('"') for line in captured.strip().split('\n')}

    # Check if only the selected keys are present in the output
    assert all(key in selected_keys for key in exported_secrets.keys())
    # Check if the values match the original secrets
    assert all(exported_secrets[key] == secrets_dict[key] for key in selected_keys)


def test_export_json(capsys):
    export_json(secrets_dict)
    captured = capsys.readouterr()
    assert json.loads(captured.out) == secrets_dict


def test_export_csv(capsys):
    export_csv(secrets_dict)
    captured = capsys.readouterr()
    reader = csv.reader(io.StringIO(captured.out))
    header = next(reader)
    assert header == ['Key', 'Value']
    for row in reader:
        assert row[0] in secrets_dict
        assert row[1] == secrets_dict[row[0]]


def test_export_yaml(capsys):
    export_yaml(secrets_dict)
    captured = capsys.readouterr()
    assert yaml.safe_load(captured.out) == secrets_dict


def test_export_xml(capsys):
    export_xml(secrets_dict)
    captured = capsys.readouterr()
    root = ET.fromstring(captured.out)
    for secret in root:
        assert secret.text == secrets_dict[secret.attrib['name']]


def test_export_dotenv(capsys):
    export_dotenv(secrets_dict)
    captured = capsys.readouterr()
    for line in captured.out.strip().split('\n'):
        key, value = line.split('=', 1)
        assert value.strip('"') == secrets_dict[key]


def test_export_toml(capsys):
    export_toml(secrets_dict)
    captured = capsys.readouterr()
    assert toml.loads(captured.out) == secrets_dict


def test_export_hcl(capsys):
    export_hcl(secrets_dict)
    captured = capsys.readouterr()
    decoded = hcl2.loads(captured.out)
    expected_structure = {'variable': []}
    for key, value in secrets_dict.items():
        expected_structure['variable'].append({key: {'default': value}})
    assert decoded == expected_structure


def test_export_ini(capsys):
    export_ini(secrets_dict)
    captured = capsys.readouterr()
    parser = ConfigParser()
    parser.read_string(captured.out)
    for key in secrets_dict:
        assert parser['DEFAULT'][key] == secrets_dict[key]


def test_export_java_properties(capsys):
    export_java_properties(secrets_dict)
    captured = capsys.readouterr()
    properties = dict(line.split('=', 1) for line in captured.out.strip().split('\n'))
    for key, value in properties.items():
        assert value == secrets_dict[key]


def test_export_kv(capsys):
    """Test the KV export format - simple key-value pairs without quotes."""
    export_kv(secrets_dict)
    captured = capsys.readouterr()
    
    # Process the output by splitting on newlines and then on '='
    exported_secrets = dict(line.split('=', 1) for line in captured.out.strip().split('\n'))
    
    # Verify all keys and values match the original secrets
    assert exported_secrets == secrets_dict


@patch('phase_cli.cmd.secrets.export.Phase')
def test_phase_secrets_env_export_kv_format(mock_phase, capsys):
    """Test the KV format when using the main export function."""
    mock_phase_instance = mock_phase.return_value
    all_secrets = [{'key': k, 'value': v, 'environment': 'development', 'application': 'test-application-name', 'path': 'dummy/path'} 
                  for k, v in secrets_dict.items()]
    mock_phase_instance.get.return_value = all_secrets

    # Call phase_secrets_env_export with kv format
    phase_secrets_env_export(format='kv')

    # Capture the output
    captured = capsys.readouterr().out

    # Process the output by splitting on newlines and then on '='
    exported_secrets = dict(line.split('=', 1) for line in captured.strip().split('\n'))

    # Verify the exported secrets match the original secrets
    assert exported_secrets == secrets_dict


@patch('phase_cli.cmd.secrets.export.Phase')
@patch('phase_cli.cmd.secrets.export.sys.exit')
def test_phase_secrets_env_export_error_handling(mock_exit, mock_phase):
    # Arrange: Set up the mock Phase instance to raise a ValueError
    mock_phase_instance = mock_phase.return_value
    error_message = "API request failed"
    mock_phase_instance.get.side_effect = ValueError(error_message)
    
    # Act: Call the function that should handle the error
    phase_secrets_env_export()
    
    # Assert: Verify sys.exit was called with exit code 1
    mock_exit.assert_called_once_with(1)


@patch('phase_cli.cmd.secrets.export.Console')
@patch('phase_cli.cmd.secrets.export.Phase')
@patch('phase_cli.cmd.secrets.export.sys.exit')
def test_phase_secrets_env_export_logs_error_message(mock_exit, mock_phase, mock_console):
    # Arrange: Set up mocks
    mock_phase_instance = mock_phase.return_value
    mock_console_instance = mock_console.return_value
    error_message = "API request failed"
    mock_phase_instance.get.side_effect = ValueError(error_message)
    
    # Act: Call the function that should handle the error
    phase_secrets_env_export()
    
    # Assert: Verify the error was logged and sys.exit was called
    mock_console_instance.log.assert_called_once_with(f"Error: {error_message}")
    mock_exit.assert_called_once_with(1)
