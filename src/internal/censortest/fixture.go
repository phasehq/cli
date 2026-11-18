package censortest

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

const (
	alnum   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	lowerHx = "0123456789abcdef"
	digits  = "0123456789"
)

// Fixture is a small, plausible app repository whose config files hold fake
// secrets where coding agents really read them, with the list of those secrets.
// Every value is fake and freshly random, in a realistic format.
type Fixture struct {
	// Files maps a path relative to the repository root to its content.
	Files map[string]string
	// Entries are the values planted in Files. An entry with Expect "rule" is
	// meant to be left out of an index: only the pattern rules can catch it.
	Entries []Entry
	// RuleOnly is how many Phase tokens Files holds that are in no entry, so
	// only the pattern rules know about them.
	RuleOnly int
}

// NewFixture makes a fixture with fresh values.
func NewFixture() *Fixture {
	b := &builder{files: map[string]string{}}
	b.app()
	b.envFiles()
	b.terraform()
	b.kubernetes()
	b.cloudAndTools()
	b.logsAndHistory()
	ruleOnly := b.ruleOnlyTokens()
	return &Fixture{Files: b.files, Entries: b.entries, RuleOnly: ruleOnly}
}

// Write puts the files under dir, which must not exist yet.
func (f *Fixture) Write(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("%s already exists", dir)
	}
	for name, content := range f.Files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return err
		}
	}
	return nil
}

type builder struct {
	files   map[string]string
	entries []Entry
}

func (b *builder) secret(id, kind, where, value string) string {
	b.entries = append(b.entries, Entry{ID: id, Type: kind, Value: value, Where: where})
	return value
}

func (b *builder) expect(id, expect string) {
	for i := range b.entries {
		if b.entries[i].ID == id {
			b.entries[i].Expect = expect
		}
	}
}

func random(alphabet string, n int) string {
	out := make([]byte, n)
	limit := big.NewInt(int64(len(alphabet)))
	for i := range out {
		k, err := rand.Int(rand.Reader, limit)
		if err != nil {
			panic(err)
		}
		out[i] = alphabet[k.Int64()]
	}
	return string(out)
}

func randomHex(bytesLong int) string {
	raw := make([]byte, bytesLong)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return hex.EncodeToString(raw)
}

func b64(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }

func b64url(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func randomBytes(n int) []byte {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return raw
}

func ecPEM(curve elliptic.Curve) string {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func rsaKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

func jwt(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": b64url(randomBytes(20)), "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	return b64url(header) + "." + b64url(payload) + "." + b64url(randomBytes(256))
}

func phaseToken(kind, version string) string {
	return "pss_" + kind + ":" + version + ":" + randomHex(32) + ":" + randomHex(32) + ":" + randomHex(32) + ":" + randomHex(32)
}

func indentJSON(value any) string {
	out, _ := json.MarshalIndent(value, "", "  ")
	return string(out) + "\n"
}

func (b *builder) app() {
	b.files["README.md"] = `# orders-service

Takes orders from the storefront, charges them with Stripe, and sends receipts.

- ` + "`src/server.js`" + `: HTTP API
- ` + "`src/db.js`" + `: Postgres access
- ` + "`k8s/`" + `: deployment manifests
- ` + "`terraform.tfstate`" + `: last applied state of the AWS stack (yes, it should be in S3)

Run locally with ` + "`docker compose up`" + `, then ` + "`npm start`" + `.
`
	b.files["package.json"] = indentJSON(map[string]any{
		"name": "orders-service", "version": "1.4.2", "private": true, "main": "src/server.js",
		"scripts":      map[string]string{"start": "node src/server.js", "test": "node --test"},
		"dependencies": map[string]string{"express": "^4.19.2", "pg": "^8.12.0", "stripe": "^16.2.0", "@slack/web-api": "^7.3.1"},
	})
	b.files[".gitignore"] = "node_modules/\n"
	b.files["src/server.js"] = `const express = require("express");
const Stripe = require("stripe");
const { pool } = require("./db");

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();
app.use(express.json());

app.post("/orders", async (req, res) => {
  const { items, customerId } = req.body;
  const total = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
  const charge = await stripe.paymentIntents.create({ amount: total, currency: "usd", customer: customerId });
  const { rows } = await pool.query("insert into orders (customer_id, total, payment_intent) values ($1, $2, $3) returning id", [customerId, total, charge.id]);
  res.status(201).json({ id: rows[0].id });
});

app.listen(process.env.PORT || 3000);
`
	b.files["src/db.js"] = `const { Pool } = require("pg");

// DATABASE_URL comes from .env locally and from the orders-secrets Secret in k8s.
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 10 });

module.exports = { pool };
`
}

func (b *builder) envFiles() {
	stripe := b.secret("stripe_secret_key", "sealed", ".env", "sk_live_51"+random(alnum, 97))
	sendgrid := b.secret("sendgrid_api_key", "secret", ".env", "SG."+random(alnum+"-_", 22)+"."+random(alnum+"-_", 43))
	jwtSecret := b.secret("jwt_secret", "secret", ".env", random(alnum, 64))
	database := b.secret("database_url", "secret", ".env", "postgres://orders_app:"+random(alnum, 24)+"@orders-db.internal.example.com:5432/orders?sslmode=require")
	b.secret("postgres_password", "secret", ".env, docker-compose.yml", "postgres")
	b.expect("postgres_password", "too_short")
	b.files[".env"] = fmt.Sprintf(`# Local development. Copy to .env.local to override.
PORT=3000
NODE_ENV=development
DATABASE_URL=%s
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
STRIPE_SECRET_KEY=%s
SENDGRID_API_KEY="%s"
JWT_SECRET='%s'
`, database, stripe, sendgrid, jwtSecret)

	jwtKey := b.secret("jwt_private_key", "sealed", ".env.production", strings.TrimSpace(ecPEM(elliptic.P256())))
	openai := b.secret("openai_api_key", "secret", ".env.production", "sk-proj-"+random(alnum+"-_", 74)+"T3BlbkFJ"+random(alnum+"-_", 74))
	redis := b.secret("redis_url", "secret", ".env.production", "rediss://default:"+random(alnum, 32)+"@orders-cache.abc123.use1.cache.amazonaws.com:6379")
	phase := b.secret("phase_service_token", "sealed", ".env.production", phaseToken("service", "v2"))
	b.files[".env.production"] = fmt.Sprintf(`NODE_ENV=production
PORT=8080
LOG_LEVEL=info
REDIS_URL=%s
OPENAI_API_KEY=%s
JWT_PRIVATE_KEY="%s"
PHASE_SERVICE_TOKEN=%s
PHASE_APP=orders-service
PHASE_ENV=production
`, redis, openai, strings.ReplaceAll(jwtKey, "\n", `\n`), phase)
}

func (b *builder) terraform() {
	rds := b.secret("rds_master_password", "sealed", "terraform.tfstate", random(alnum+"!#%^*-_", 28))
	accessKeyID := "AKIA" + random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16) // in no entry: the AWS rule catches it
	iamSecret := b.secret("aws_iam_secret_key", "sealed", "terraform.tfstate", random(alnum+"/+", 40))
	webhook := b.secret("webhook_signing_secret", "secret", "terraform.tfstate (base64)", "whsec_"+random(alnum, 32))
	partner := b.secret("partner_api_key", "secret", "terraform.tfstate (nested JSON string)", "ptn_live_"+random(alnum, 40))
	partnerJSON, _ := json.Marshal(map[string]string{"username": "orders-sync", "api_key": partner, "endpoint": "https://partner.example.com/v2"})
	resource := func(kind, name string, attributes map[string]any) map[string]any {
		return map[string]any{"mode": "managed", "type": kind, "name": name, "provider": `provider["registry.terraform.io/hashicorp/aws"]`,
			"instances": []any{map[string]any{"schema_version": 0, "attributes": attributes, "sensitive_attributes": []any{}}}}
	}
	b.files["terraform.tfstate"] = indentJSON(map[string]any{
		"version": 4, "terraform_version": "1.9.5", "serial": 42, "lineage": randomUUID(),
		"outputs": map[string]any{"db_endpoint": map[string]any{"value": "orders-db.c9x2abcd1234.us-east-1.rds.amazonaws.com:5432", "type": "string"}},
		"resources": []any{
			resource("aws_db_instance", "orders", map[string]any{"identifier": "orders-db", "engine": "postgres", "engine_version": "16.3",
				"instance_class": "db.t4g.medium", "username": "orders_admin", "password": rds, "allocated_storage": 50, "multi_az": true}),
			resource("aws_iam_access_key", "ci_deployer", map[string]any{"user": "orders-ci", "id": accessKeyID, "secret": iamSecret, "status": "Active"}),
			resource("aws_secretsmanager_secret_version", "webhook", map[string]any{"secret_id": "arn:aws:secretsmanager:us-east-1:123456789012:secret:orders/webhook-" + random(alnum, 6),
				"secret_binary": b64(webhook), "version_stages": []string{"AWSCURRENT"}}),
			resource("aws_secretsmanager_secret_version", "partner", map[string]any{"secret_id": "arn:aws:secretsmanager:us-east-1:123456789012:secret:orders/partner-" + random(alnum, 6),
				"secret_string": string(partnerJSON), "version_stages": []string{"AWSCURRENT"}}),
		},
	})
}

func randomUUID() string {
	raw := randomBytes(16)
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	h := hex.EncodeToString(raw)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func (b *builder) kubernetes() {
	slack := b.secret("slack_bot_token", "secret", "k8s/secret.yaml (data, base64)", "xoxb-"+random(digits, 13)+"-"+random(digits, 13)+"-"+random(alnum, 24))
	session := b.secret("session_secret", "secret", "k8s/secret.yaml (stringData)", random(alnum, 48))
	b.files["k8s/secret.yaml"] = fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: orders-secrets
  namespace: orders
type: Opaque
data:
  SLACK_BOT_TOKEN: %s
  LOG_LEVEL: %s
stringData:
  SESSION_SECRET: %s
`, b64(slack), b64("info"), session)

	smtp := b.secret("smtp_password", "secret", "k8s/kubectl-get-secret.json (data, base64)", random(alnum, 32))
	b.files["k8s/kubectl-get-secret.json"] = indentJSON(map[string]any{
		"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
		"metadata": map[string]any{"name": "orders-smtp", "namespace": "orders", "uid": randomUUID(), "resourceVersion": random(digits, 8), "creationTimestamp": "2026-10-02T09:14:51Z"},
		"data":     map[string]string{"SMTP_HOST": b64("smtp.mailgun.org"), "SMTP_USER": b64("postmaster@mg.orders.example.com"), "SMTP_PASSWORD": b64(smtp)},
	})

	registry := b.secret("registry_token", "secret", "k8s/registry-secret.yaml (.dockerconfigjson)", "dckr_pat_"+random(alnum+"-_", 27))
	dockerConfig, _ := json.Marshal(map[string]any{"auths": map[string]any{"https://index.docker.io/v1/": map[string]string{
		"username": "ordersbot", "password": registry, "auth": b64("ordersbot:" + registry)}}})
	b.files["k8s/registry-secret.yaml"] = fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: regcred
  namespace: orders
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: %s
`, b64(string(dockerConfig)))

	// Helm keeps a release as gzip and then base64: caught by inflating the run.
	helmKey := b.secret("helm_values_api_key", "secret", "k8s/helm-release.yaml (gzip+base64)", random(alnum, 40))
	release, _ := json.Marshal(map[string]any{"name": "orders", "version": 7, "namespace": "orders",
		"chart":  map[string]any{"metadata": map[string]any{"name": "orders", "version": "1.4.2", "appVersion": "1.4.2"}},
		"config": map[string]any{"replicaCount": 3, "image": map[string]string{"repository": "ordersbot/orders", "tag": "1.4.2"}, "analytics": map[string]string{"apiKey": helmKey}},
		"info":   map[string]any{"status": "deployed", "first_deployed": "2026-09-14T10:02:11Z", "description": "Upgrade complete"}})
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, _ = gz.Write(release)
	_ = gz.Close()
	b.files["k8s/helm-release.yaml"] = fmt.Sprintf(`# kubectl get secret sh.helm.release.v1.orders.v7 -o yaml (data field decoded once)
apiVersion: v1
kind: Secret
metadata:
  name: sh.helm.release.v1.orders.v7
  namespace: orders
  labels:
    name: orders
    owner: helm
    status: deployed
    version: "7"
type: helm.sh/release.v1
release: %s
`, base64.StdEncoding.EncodeToString(compressed.Bytes()))

	kubeToken := b.secret("kube_sa_token", "secret", "kubeconfig (token)", jwt(map[string]any{
		"iss": "kubernetes/serviceaccount", "kubernetes.io/serviceaccount/namespace": "orders",
		"kubernetes.io/serviceaccount/service-account.name": "deployer", "sub": "system:serviceaccount:orders:deployer"}))
	clientKey := b.secret("kube_client_key", "sealed", "kubeconfig (client-key-data, base64)", strings.TrimSpace(ecPEM(elliptic.P384())))
	b.files["kubeconfig"] = fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: orders-prod
  cluster:
    server: https://4F2C9A1B7E.gr7.us-east-1.eks.amazonaws.com
    certificate-authority-data: %s
contexts:
- name: orders-prod
  context:
    cluster: orders-prod
    user: deployer
    namespace: orders
current-context: orders-prod
users:
- name: deployer
  user:
    token: %s
- name: admin-cert
  user:
    client-certificate-data: %s
    client-key-data: %s
`, b64("-----BEGIN CERTIFICATE-----\n"+base64.StdEncoding.EncodeToString(randomBytes(300))+"\n-----END CERTIFICATE-----\n"), kubeToken,
		b64("-----BEGIN CERTIFICATE-----\n"+base64.StdEncoding.EncodeToString(randomBytes(300))+"\n-----END CERTIFICATE-----\n"), b64(clientKey+"\n"))
}

func (b *builder) cloudAndTools() {
	key := rsaKey()
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	project := "orders-prod-" + random(digits, 6)
	account := indentJSON(map[string]string{
		"type": "service_account", "project_id": project, "private_key_id": randomHex(20),
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": "orders-deployer@" + project + ".iam.gserviceaccount.com", "client_id": random(digits, 21),
		"auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url":        "https://www.googleapis.com/robot/v1/metadata/x509/orders-deployer%40" + project + ".iam.gserviceaccount.com",
		"universe_domain":             "googleapis.com",
	})
	b.files["gcp-service-account.json"] = b.secret("gcp_service_account", "sealed", "gcp-service-account.json", account)

	ciSecret := b.secret("aws_secret_access_key_ci", "sealed", "aws-credentials", random(alnum+"/+", 40))
	b.files["aws-credentials"] = fmt.Sprintf(`[default]
region = us-east-1

[orders-ci]
aws_access_key_id = AKIA%s
aws_secret_access_key = %s
region = us-east-1
`, random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16), ciSecret)

	npm := b.secret("npm_token", "secret", ".npmrc", "npm_"+random(alnum, 36))
	b.files[".npmrc"] = "@orders:registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=" + npm + "\nalways-auth=true\n"

	github := b.secret("github_token_netrc", "secret", ".netrc", "ghp_"+random(alnum, 36))
	b.files[".netrc"] = "machine github.com\n  login orders-bot\n  password " + github + "\n"

	webhookSecret := b.secret("payments_webhook_secret", "secret", "config/app.ini (keyword only)", keywordOnlyValue(32))
	b.expect("payments_webhook_secret", "rule")
	b.files["config/app.ini"] = "[server]\nport = 8080\nworkers = 4\n\n[payments]\nprovider = stripe\nwebhook_secret = " + webhookSecret + "\nretry_limit = 5\n"

	mailgun := b.secret("mailgun_api_key", "secret", "docker-compose.yml", randomHex(16)+"-"+randomHex(4)+"-"+randomHex(4))
	reporting := b.secret("reporting_api_key", "secret", "docker-compose.yml (keyword only)", keywordOnlyValue(28))
	b.expect("reporting_api_key", "rule")
	b.files["docker-compose.yml"] = fmt.Sprintf(`services:
  api:
    build: .
    ports: ["3000:3000"]
    env_file: .env
    environment:
      MAILGUN_DOMAIN: mg.orders.example.com
      MAILGUN_API_KEY: %s
      REPORTING_API_KEY: %s
    depends_on: [db]
  db:
    image: postgres:16
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: orders
    ports: ["5432:5432"]
`, mailgun, reporting)

	rails := b.secret("rails_db_password", "secret", "config/database.yml", random(alnum, 32))
	b.files["config/database.yml"] = fmt.Sprintf(`# Used by the admin console (legacy Rails app in admin/).
default: &default
  adapter: postgresql
  encoding: unicode
  pool: 5

development:
  <<: *default
  database: orders_development
  username: postgres
  password: postgres

production:
  <<: *default
  host: orders-db.internal.example.com
  database: orders
  username: orders_admin_console
  password: %s
`, rails)

	tlsKey := rsaKey()
	tlsPEM := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(tlsKey)})))
	b.files["deploy/server.pem"] = b.secret("tls_private_key", "sealed", "deploy/server.pem", tlsPEM) + "\n"

	vercel := b.secret("vercel_token", "secret", ".github/workflows/deploy.yml", random(alnum, 24))
	b.files[".github/workflows/deploy.yml"] = fmt.Sprintf(`name: deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm ci && npm test
      # TODO move this into repository secrets
      - run: npx vercel deploy --prod --token=%s
`, vercel)
}

// keywordOnlyValue has no known prefix or shape: only a keyword nearby gives it away.
func keywordOnlyValue(n int) string {
	return random(alnum, n-2) + random(digits, 1) + random("abcdefghijklmnopqrstuvwxyz", 1)
}

func (b *builder) logsAndHistory() {
	bearer := b.secret("internal_api_jwt", "secret", "logs/app.log (bearer token)", jwt(map[string]any{
		"iss": "https://auth.orders.example.com", "sub": "svc-fulfilment", "aud": "orders-api", "scope": "orders:write", "exp": 1798761600}))
	mssql := b.secret("mssql_password", "secret", "logs/app.log (connection string)", random(alnum+"!#", 20))
	clientSecret := b.secret("oauth_client_secret", "secret", "logs/app.log (keyword only)", keywordOnlyValue(40))
	b.expect("oauth_client_secret", "rule")
	b.files["logs/app.log"] = fmt.Sprintf(`2026-11-14T09:12:03.114Z info  server listening on :8080
2026-11-14T09:12:03.902Z info  connected to postgres orders-db.internal.example.com:5432/orders
2026-11-14T09:14:27.551Z debug outbound request POST https://fulfilment.internal.example.com/v1/shipments headers={"Authorization":"Bearer %s","Content-Type":"application/json"}
2026-11-14T09:14:27.802Z warn  fulfilment answered 503, retrying in 2s
2026-11-14T09:15:10.004Z error legacy reporting sync failed: Login failed for connection "Server=tcp:orders-sql.database.windows.net,1433;Initial Catalog=reporting;User ID=orders_report;Password=%s;Encrypt=True;"
2026-11-14T09:15:10.006Z info  reporting sync will retry at 09:30
2026-11-14T09:20:44.310Z debug token refresh for carrier api client_id=orders-fulfilment client_secret=%s
`, bearer, mssql, clientSecret)

	anthropic := b.secret("anthropic_api_key", "secret", "ops/shell_history (export)", "sk-ant-api03-"+random(alnum+"-_", 93)+"AA")
	grafana := b.secret("grafana_admin_password", "secret", "ops/shell_history (curl -u)", random(alnum, 20))
	b.files["ops/shell_history"] = fmt.Sprintf(`: 1731570001:0;cd ~/git/orders-service
: 1731570012:0;kubectl -n orders get pods
: 1731570040:0;export ANTHROPIC_API_KEY=%s
: 1731570077:0;curl -s -u admin:%s https://grafana.internal.example.com/api/dashboards/uid/orders | jq .
: 1731570102:0;terraform plan -out plan.tfplan
: 1731570150:0;git push origin main
`, anthropic, grafana)
}

// ruleOnlyTokens writes Phase tokens that are deliberately in no entry, so
// only the pattern rules can catch them. It returns how many it wrote.
func (b *builder) ruleOnlyTokens() int {
	b.files["scripts/bootstrap.sh"] = fmt.Sprintf(`#!/bin/sh
# Pulls secrets into the shell for a one-off migration. Delete after use.
set -eu
export PHASE_SERVICE_TOKEN=%s
# Personal token, only for the first run against staging
export PHASE_TOKEN=%s
phase run --app orders-service --env staging -- npm run migrate
`, phaseToken("service", "v2"), phaseToken("user", "v1"))
	return 2
}
