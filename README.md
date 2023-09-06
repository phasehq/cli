# Phase-CLI

```
Securely manage and sync environment variables with Phase.

         :@tX88%%:
        ;X;%;@%8X@;
      ;Xt%;S8:;;t%S
      ;SXStS@.;t8@:;.
    ;@:t;S8  ;@.%.;8:
    :X:S%88    S.88t:.
  :X:%%88     :S:t.t8t
.@8X888@88888888X8.%8X8888888X8.S88:
                ;t;X8;      ;XS:%X;
                :@:8@X.     XXS%S8
                 8XX:@8S  .X%88X;
                  .@:XX88:8Xt8:
                     :%88@S8:

options:
  -h, --help            show this help message and exit
  --version, -v         show program's version number and exit

Commands:
  {auth,init,run,secrets,logout,console,update,keyring}
    auth                💻 Authenticate with Phase
    init                🔗 Link your project to your Phase app
    run                 🚀 Run and inject secrets to your app
    secrets             🗝️` Manage your secrets
    logout              🏃 Logout from phase-cli
    console             🖥️` Open the Phase Console in your browser
    update              🔄 Update the Phase CLI to the latest version
    keyring             🔐 Display information about the Phase keyring
```

## Features

- Inject secrets to your application during runtime without any code changes
- Import your existing .env files and encrypt them
- Sync encrypted secrets with Phase cloud
- Multiple environments eg. dev, testing, staging, production

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
