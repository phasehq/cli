import pytest
from phase_cli.utils.misc import tag_matches, normalize_tag


full_tag_names = {
    "prod": ["Production", "ProdData", "NonProd_Environment"],
    "config": ["ConfigData", "Configuration", "config_file"],
    "test": ["Test_Tag", "testEnvironment", "Testing_Data"],
    "dev": ["DevEnv", "DevelopmentData", "dev_tools"],
    "prod_data": ["prod_data"],
    "DEV_ENV": []  # No matching tags under the current logic
}


def test_normalize_tag():
    for tag in full_tag_names:
        normalized_tag = normalize_tag(tag)
        assert normalized_tag == tag.replace('_', ' ').lower(), f"Normalization failed for tag: {tag}"


def test_tag_matches():
    for tag, secret_tags in full_tag_names.items():
        normalized_tag = normalize_tag(tag)

        # Test for matching scenarios
        for secret_tag in secret_tags:
            normalized_secret_tag = normalize_tag(secret_tag)
            assert normalized_tag in normalized_secret_tag, f"Tag '{tag}' should match with secret tag '{secret_tag}'"
