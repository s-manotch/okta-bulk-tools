# Okta Bulk User Tool v0.3

Internal web GUI for common Okta onboarding operations.

## Features

- **Create Users** from one CSV
  - validates required fields
  - detects existing logins
  - assigns one or more global groups selected in the GUI
  - optional per-row groups from the CSV
  - detailed partial-failure reporting
- **Send / Resend Activation** by loading all pending users from Okta
  - includes `STAGED` users (send first activation) and `PROVISIONED` users (resend)
  - select individual users or all eligible users before sending
- **User Lookup** by Okta login
- OAuth 2.0 Service App (`private_key_jwt`) or temporary SSWS token mode
- Basic Auth for the GUI
- retry on HTTP 429 and configurable delay between write operations
- activation mail is processed in small batches (20, 30, or 50); the server enforces `MAX_ACTIVATION_BATCH`
- result CSV downloads

## Create-user CSV

Required columns:

```csv
firstName,lastName,login,email
Alice,Example,alice.user@example.com,alice.notify@example.com
```

Optional columns:

```csv
firstName,lastName,login,email,department,groups
Alice,Example,alice.user@example.com,alice.notify@example.com,DeptA,legal
Jane,Doe,jane.d@example.com,jane.d.notify@example.com,DeptB,"legal;zpa-user"
```

The GUI can also assign a **global group** to every new user, so a normal onboarding CSV does not need a group column at all.

Workflow:

```text
CSV -> Preview/validate -> re-check existence -> create STAGED user
    -> add selected group memberships
```

The tool intentionally creates the user with `activate=false` and adds groups first. Use the **Send / Resend Activation** tab afterwards to load `STAGED` / `PROVISIONED` users, select the intended recipients, and ask Okta to send their activation email.

## OAuth Service App

Recommended scopes for this version:

```text
okta.users.manage okta.groups.manage
```

The Service App also needs an Admin Role / Resource Set that actually permits the corresponding user and group-membership operations. OAuth scopes alone do not grant admin permissions.

For production, prefer a least-privilege custom admin role rather than Super Admin.

## Quick start

```bash
cp .env.example .env
# Build the image, then generate the web-login hash and copy the printed value into .env
docker compose build
docker compose run --rm web python tools/hash_password.py

# Set OKTA_DOMAIN and OKTA_TOKEN in .env, then protect the file
chmod 600 .env
docker compose up -d --build
```

The compose file binds only to:

```text
127.0.0.1:8080
```

Publish it through an internal Nginx / ZPA path rather than exposing port 8080 publicly.

## Resend Activation CSV

```csv
login
alice.user@example.com
user2@example.com
```

Use Okta `profile.login`, which may differ from the user's delivery email.

## Security notes

- Keep `.env` and `private_jwk.json` out of Git.
- `WEB_PASSWORD_HASH_B64` is a salted bcrypt one-way hash; the original web password is never stored.
- An SSWS API token cannot use a one-way hash because the app must send the original token to Okta. Therefore `OKTA_TOKEN` is plaintext in `.env`; use server secret management or OAuth when you are ready to harden the deployment.
- Start activation email with batches of 20 and keep `SEND_DELAY_SECONDS=1.0` or higher when your mail gateway is sensitive to message bursts. The UI never sends more than `MAX_ACTIVATION_BATCH` recipients in one request.
- Keep the private JWK on the server only.
- Put the app behind an HTTPS-enabled ZPA/internal reverse proxy; HTTP Basic credentials are not encrypted without TLS.
- Keep Preview as the normal first step.
- Activation is opt-in on Create Users; it is not enabled by default.
- Result rows distinguish create, group, and activation failures so partial operations are visible.
