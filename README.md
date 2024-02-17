# Phase-CLI

```
λ phase
Securely manage and sync environment variables with Phase.

⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠔⠋⣳⣖⠚⣲⢖⠙⠳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡴⠉⢀⡼⠃⢘⣞⠁⠙⡆⠀⠘⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⡜⠁⢠⠞⠀⢠⠞⠸⡆⠀⠹⡄⠀⠹⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⠞⠀⢠⠏⠀⣠⠏⠀⠀⢳⠀⠀⢳⠀⠀⢧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⠎⠀⣠⠏⠀⣰⠃⠀⠀⠀⠈⣇⠀⠘⡇⠀⠘⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢠⠏⠀⣰⠇⠀⣰⠃⠀⠀⠀⠀⠀⢺⡀⠀⢹⠀⠀⢽⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢠⠏⠀⣰⠃⠀⣰⠃⠀⠀⠀⠀⠀⠀⠀⣇⠀⠈⣇⠀⠘⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢠⠏⠀⢰⠃⠀⣰⠃⠀⠀⠀⠀⠀⠀⠀⠀⢸⡀⠀⢹⡀⠀⢹⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢠⠏⠀⢰⠃⠀⣰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣇⠀⠈⣇⠀⠈⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠛⠒⠚⠛⠒⠓⠚⠒⠒⠓⠒⠓⠚⠒⠓⠚⠒⠓⢻⡒⠒⢻⡒⠒⢻⡒⠒⠒⠒⠒⠒⠒⠒⠒⠒⣲⠒⠒⣲⠒⠒⡲⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢧⠀⠀⢧⠀⠈⣇⠀⠀⠀⠀⠀⠀⠀⠀⢠⠇⠀⣰⠃⠀⣰⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡆⠀⠘⡆⠀⠸⡄⠀⠀⠀⠀⠀⠀⣠⠇⠀⣰⠃⠀⣴⠃⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⡄⠀⠹⡄⠀⠹⡄⠀⠀⠀⠀⡴⠃⢀⡼⠁⢀⡼⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣆⠀⠙⣆⠀⠹⣄⠀⣠⠎⠁⣠⠞⠀⡤⠏⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⢤⣈⣳⣤⣼⣹⢥⣰⣋⡥⡴⠊⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀

Options:
  -h, --help   show this help message and exit
  --version, -v
               show program's version number and exit

Commands:

    auth             💻 Authenticate with Phase
    init             🔗 Link your project with your Phase app
    run              🚀 Run and inject secrets to your app
    secrets          🗝️ Manage your secrets
    secrets list     📇 List all the secrets
    secrets get      🔍 Get a specific secret by key
    secrets create   💳 Create a new secret
    secrets update   📝 Update an existing secret
    secrets delete   🗑️ Delete a secret
    secrets import   📩 Import secrets from a .env file
    secrets export   🥡 Export secrets in a dotenv format
    users            👥 Manage users and accounts
    users whoami     🙋 See details of the current user
    users logout     🏃 Logout from phase-cli
    users keyring    🔐 Display information about the Phase keyring
    console          🖥️ Open the Phase Console in your browser
    update           🆙 Update the Phase CLI to the latest version
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
curl -fsSL https://get.phase.dev | bash
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

### Make sure virtualenv is installed

```bash
pip3 install virtualenv

```

### Create a virtualenv:

```bash
virtualenv phase-cli
```

### Switch to the virtualenv:

```bash
source phase-cli/bin/activate
```

### Install dependencies:

```bash
 pip3 install -r requirements.txt
```

```
export PYTHONPATH="$PWD"
```

```bash
./phase_cli/main.py
```
