# phase cli

```fish
λ phase --help
Securely manage application secrets and environment variables with Phase.

           /$$
          | $$
  /$$$$$$ | $$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$
 /$$__  $$| $$__  $$ |____  $$ /$$_____/ /$$__  $$
| $$  \ $$| $$  \ $$  /$$$$$$$|  $$$$$$ | $$$$$$$$
| $$  | $$| $$  | $$ /$$__  $$ \____  $$| $$_____/
| $$$$$$$/| $$  | $$|  $$$$$$$ /$$$$$$$/|  $$$$$$$
| $$____/ |__/  |__/ \_______/|_______/  \_______/
| $$
|__/

options:
  -h, --help   show this help message and exit
  --version, -v
               show program's version number and exit
Commands:

    auth                             💻 Authenticate with Phase
    init                             🔗 Link your project with your Phase app
    run                              🚀 Run and inject secrets to your app
    shell                            🐚 Launch a sub-shell with secrets as environment variables (BETA)
    secrets                          🗝️ Manage your secrets
    secrets list                     📇 List all the secrets
    secrets get                      🔍 Get a specific secret by key
    secrets create                   💳 Create a new secret
    secrets update                   📝 Update an existing secret
    secrets delete                   🗑️ Delete a secret
    secrets import                   📩 Import secrets from a .env file
    secrets export                   🥡 Export secrets in a dotenv format
    dynamic-secrets                  ⚡️ Manage dynamic secrets
    dynamic-secrets list             📇 List dynamic secrets & metadata
    dynamic-secrets lease            📜 Manage dynamic secret leases
    dynamic-secrets lease get        🔍 Get leases for a dynamic secret
    dynamic-secrets lease renew      🔁 Renew a lease
    dynamic-secrets lease revoke     🗑️ Revoke a lease
    dynamic-secrets lease generate   ✨ Generate a lease (create fresh dynamic secrets)
    users                            👥 Manage users and accounts
    users whoami                     🙋 See details of the current user
    users switch                     🪄 Switch between Phase users, orgs and hosts
    users logout                     🏃 Logout from phase-cli
    users keyring                    🔐 Display information about the Phase keyring
    docs                             📖 Open the Phase CLI Docs in your browser
    console                          🖥️ Open the Phase Console in your browser
    update                           🆙 Update the Phase CLI to the latest version
```

## Features

- Inject secrets to your application during runtime without any code changes
- Import your existing .env files and encrypt them
- Sync encrypted secrets with Phase cloud
- Multiple environments eg. dev, testing, staging, production

## See it in action

[![asciicast](media/phase-cli-demo.gif)](asciinema-cli-demo)

## Installation

You can install Phase-CLI using curl:

```bash
curl -fsSL https://pkg.phase.dev/install.sh | bash
```

## Usage

### Login

Create an app in the [Phase Console](https://console.phase.dev) and copy appID and pss

```bash
phase auth
```

### Initialize

Link the phase cli to your project

```bash
phase init
```

### Import .env

Import and encrypt existing secrets and environment variables

```bash
phase secrets import .env
```

## List / view secrets

```bash
phase secrets list --show
```

## Run and inject secrets

`phase run // your run command`

Example:

```bash
phase run yarn dev
```

```bash
phase run go run
```

```bash
phase run npm start
```

## Development:

### Create a virtualenv:

```bash
python -m venv venv
```

### Switch to the virtualenv:

```bash
source venv/bin/activate
```

### Install dependencies:

```bash
pip install -r requirements.txt
```

### Install the CLI in editable mode:

```bash
pip install -e .
```

```bash
phase --version
```