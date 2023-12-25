import pytest
import json
import yaml
import csv
import io
import toml
from xml.etree import ElementTree as ET
from configparser import ConfigParser
import hcl2
from phase_cli.cmd.secrets.export import (
    export_json, export_csv, export_yaml, export_toml, export_xml, 
    export_dotenv, export_hcl, export_ini, export_java_properties
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

# TODO: Validate HCL output
# def test_export_hcl(capsys):
#     export_hcl(secrets_dict)
#     captured = capsys.readouterr()
#     decoded = hcl2.loads(captured.out)
#     expected_structure = {'variable': []}
#     for key, value in secrets_dict.items():
#         expected_structure['variable'].append({key: {'default': value}})
#     assert decoded == expected_structure


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

