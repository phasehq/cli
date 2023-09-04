import os
from setuptools import setup, find_packages

# Read the contents of the README.md file
with open('README.md', 'r') as f:
    long_description = f.read()

# Read the contents of the requirements.txt file
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

# Fetch version from environment variable or set to a default
version = os.environ.get('PHASE_CLI_VERSION')

setup(
    name='phase-cli',
    version=version,
    author='Phase',
    author_email='info@phase.dev',
    description='Securely manage your secrets and environment variables with Phase.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/phasehq/cli',
    packages=find_packages(include=['phase_cmd*', 'utils*', 'phase_cli*']),
    entry_points={
        'console_scripts': [
            'phase=phase_cli.main:main',
        ],
    },
    install_requires=requirements,
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
