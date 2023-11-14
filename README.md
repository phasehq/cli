# Phase-CLI

kubectl apply -f crd-template.yml



phase secrets export | kubectl create secret generic phase-secerts-example --from-env-file=/dev/stdin

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: helloworld-deployment
spec:
  selector:
    matchLabels:
      app: helloworld
  replicas: 1
  template:
    metadata:
      labels:
        app: helloworld
    spec:
      containers:
      - name: helloworld
        image: nginx
        ports:
        - containerPort: 80
        envFrom:
        - secretRef:
            name: phase-secerts-example
```

sudo kubectl apply -f hello-world.yml

sudo kubectl describe secret

sudo kubectl exec -it helloworld-deployment-78dcb6bd8f-jldzs -- /bin/sh

λ sudo kubectl get secret phase-secerts-example -o jsonpath='{.data}'

{"AWS_ACCESS_KEY_ID":"IkFLSUFJWDRPTlJTRzZPREVGVkpBIg==","AWS_SECRET_ACCESS_KEY":"ImFDUkFNYXJFYkZDM1E1YzI0cGk3QVZNSXQ2VGFDZkhlRlo0S0NmL2Ei","DB_HOST":"Im1jLWxhcmVuLXByb2QtZGIuYzl1ZnpqdHBsc2FxLnVzLXdlc3QtMS5yZHMuYW1hem9uYXdzLmNvbSI=","DB_NAME":"IlhQMV9MTSI=","DB_PASSWORD":"IjZjMzc4MTBlYzZlNzRlYzMyMjg0MTZkMjg0NDU2NGZjZWI5OWViZDk0YjI5ZjQzMzRjMjQ0ZGIwMTE2MzBiMGUi","DB_PORT":"IjU0MzIi","DB_USER":"InBvc3RncmVzIg==","DJANGO_DEBUG":"IlRydWUi","DJANGO_SECRET_KEY":"Ind3ZioyIzg2dDY0IWZnaDZ5YXYkYW9ldW9AdTJvQGZ5JipnZzc2cSEmJTZ4X3diZHVhZCI=","JWT_SECRET":"ImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp5YjJ4bElqb2ljMlZ5ZG1salpWOXliMnhsSWl3aWFXRjBJam94TmpNek5qSXdNVGN4TENKbGVIQWlPakl5TURnNU9EVXlNREI5LnBIbmNrYWJiTWJ3VEhBSk9rYjVaN0c3QjRjaFk2R2xsSmY2SzJtOTZ6M0Ei","POSTGRES_CONNECTION_STRING":"InBvc3RncmVzcWw6Ly9wb3N0Z3Jlczo2YzM3ODEwZWM2ZTc0ZWMzMjI4NDE2ZDI4NDQ1NjRmY2ViOTllYmQ5NGIyOWY0MzM0YzI0NGRiMDExNjMwYjBlQG1jLWxhcmVuLXByb2QtZGIuYzl1ZnpqdHBsc2FxLnVzLXdlc3QtMS5yZHMuYW1hem9uYXdzLmNvbTo1NDMyL1hQMV9MTSI=","STRIPE_SECRET_KEY":"InNrX3Rlc3RfRWVIbkw2NDRpNnpvNEl5cTR2MUtkVjlIIg=="}


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

Development:

```bash
cd /root of this git repo

export PYTHONPATH="$PWD"

./phase_cli/main.py

```
