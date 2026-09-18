# Okta Bulk User Tool v0.3

Internal web GUI for common Okta onboarding operations.

## Features

- **Create Users** from one CSV
  - validates required fields
  - detects existing logins
  - assigns one or more global groups selected in the GUI
  - optional per-row groups from the CSV
  - optional activation email after creation
  - detailed partial-failure reporting
- **Resend Activation** for existing `PROVISIONED` users
- **User Lookup** by Okta login
- OAuth 2.0 Service App (`private_key_jwt`) or temporary SSWS token mode
- Basic Auth for the GUI
- retry on HTTP 429 and configurable delay between write operations
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
    -> add selected group memberships -> optional activate + send email
```

The tool intentionally creates the user with `activate=false`, adds groups, and only then activates the user when activation mail is requested. This avoids having to import a second group-assignment CSV.

## OAuth Service App

Recommended scopes for this version:

```text
okta.users.manage okta.groups.manage
```

The Service App also needs an Admin Role / Resource Set that actually permits the corresponding user and group-membership operations. OAuth scopes alone do not grant admin permissions.

For production, prefer a least-privilege custom admin role rather than Super Admin.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Generate the web-login hash and copy the printed value into .env
python -m app.secret_tool hash-password

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
- `WEB_PASSWORD_HASH_B64` is a salted scrypt one-way hash; the original web password is never stored.
- An SSWS API token cannot use a one-way hash because the app must send the original token to Okta. Therefore `OKTA_TOKEN` is plaintext in `.env`; use server secret management or OAuth when you are ready to harden the deployment.
- Keep the private JWK on the server only.
- Put the app behind an HTTPS-enabled ZPA/internal reverse proxy; HTTP Basic credentials are not encrypted without TLS.
- Keep Preview as the normal first step.
- Activation is opt-in on Create Users; it is not enabled by default.
- Result rows distinguish create, group, and activation failures so partial operations are visible.
