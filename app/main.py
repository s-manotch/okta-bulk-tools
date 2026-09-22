import asyncio
import csv
import io
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from jwt.algorithms import ECAlgorithm, RSAAlgorithm
from pydantic import BaseModel

from app.security import verify_password_b64

load_dotenv()

app = FastAPI(title="Okta Bulk User Tool", version="0.3.0")
templates = Jinja2Templates(directory="app/templates")
security = HTTPBasic(auto_error=False)

OKTA_DOMAIN = os.getenv("OKTA_DOMAIN", "").rstrip("/")
AUTH_MODE = os.getenv("OKTA_AUTH_MODE", "oauth").lower()
CLIENT_ID = os.getenv("OKTA_CLIENT_ID", "")
PRIVATE_JWK_FILE = os.getenv("OKTA_PRIVATE_JWK_FILE", "/run/secrets/okta_private_jwk.json")
SCOPES = os.getenv("OKTA_SCOPES", "okta.users.manage okta.groups.manage")
SSWS_TOKEN = os.getenv("OKTA_TOKEN", "")
SEND_DELAY = float(os.getenv("SEND_DELAY_SECONDS", "1.0"))
API_RETRY_429 = int(os.getenv("API_RETRY_429", "2"))
MAX_ACTIVATION_BATCH = int(os.getenv("MAX_ACTIVATION_BATCH", "50"))
ACTIVATION_COOLDOWN_HOURS = float(os.getenv("ACTIVATION_COOLDOWN_HOURS", "24"))
ACTIVATION_DB_PATH = os.getenv("ACTIVATION_DB_PATH", "/data/okta_bulk_tool.db")
WEB_USERNAME = os.getenv("WEB_USERNAME", "")
WEB_PASSWORD_HASH_B64 = os.getenv("WEB_PASSWORD_HASH_B64", "")

_token_cache: dict[str, Any] = {"token": None, "expires_at": 0}
activation_jobs: dict[str, dict[str, Any]] = {}


def activation_db() -> sqlite3.Connection:
    Path(ACTIVATION_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(ACTIVATION_DB_PATH, timeout=10)
    connection.execute(
        """CREATE TABLE IF NOT EXISTS activation_sends (
            user_id TEXT PRIMARY KEY,
            login TEXT NOT NULL,
            last_sent_at INTEGER NOT NULL
        )"""
    )
    return connection


def activation_cooldown_seconds() -> int:
    return max(0, int(ACTIVATION_COOLDOWN_HOURS * 3600))


def users_in_activation_cooldown(user_ids: list[str]) -> set[str]:
    if not user_ids or activation_cooldown_seconds() == 0:
        return set()
    placeholders = ",".join("?" for _ in user_ids)
    cutoff = int(time.time()) - activation_cooldown_seconds()
    with activation_db() as connection:
        rows = connection.execute(
            f"SELECT user_id FROM activation_sends WHERE last_sent_at >= ? AND user_id IN ({placeholders})",
            [cutoff, *user_ids],
        ).fetchall()
    return {row[0] for row in rows}


def activation_cooldown_remaining(user_id: str | None) -> int:
    if not user_id or activation_cooldown_seconds() == 0:
        return 0
    with activation_db() as connection:
        row = connection.execute("SELECT last_sent_at FROM activation_sends WHERE user_id = ?", [user_id]).fetchone()
    if not row:
        return 0
    return max(0, row[0] + activation_cooldown_seconds() - int(time.time()))


def record_activation_sent(user_id: str, login: str) -> None:
    with activation_db() as connection:
        connection.execute(
            """INSERT INTO activation_sends (user_id, login, last_sent_at) VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET login = excluded.login, last_sent_at = excluded.last_sent_at""",
            [user_id, login, int(time.time())],
        )


def activation_cooldown_records() -> list[dict[str, Any]]:
    if activation_cooldown_seconds() == 0:
        return []
    cutoff = int(time.time()) - activation_cooldown_seconds()
    with activation_db() as connection:
        rows = connection.execute(
            "SELECT user_id, login, last_sent_at FROM activation_sends WHERE last_sent_at >= ? ORDER BY last_sent_at DESC",
            [cutoff],
        ).fetchall()
    return [{"id": row[0], "login": row[1], "last_sent_at": row[2]} for row in rows]


def require_web_auth(credentials: HTTPBasicCredentials | None = Depends(security)):
    if not WEB_USERNAME and not WEB_PASSWORD_HASH_B64:
        return True
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Basic"})
    ok_user = secrets.compare_digest(credentials.username, WEB_USERNAME)
    ok_pass = verify_password_b64(credentials.password, WEB_PASSWORD_HASH_B64)
    if not (ok_user and ok_pass):
        raise HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Authenticate": "Basic"})
    return True


def load_private_jwk() -> dict[str, Any]:
    try:
        with open(PRIVATE_JWK_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as e:
        raise RuntimeError(f"Private JWK file not found: {PRIVATE_JWK_FILE}") from e

    if "keys" in data:
        if not data["keys"]:
            raise RuntimeError("JWK file has an empty keys array")
        return data["keys"][0]
    return data


def private_key_from_jwk(jwk_data: dict[str, Any]):
    raw = json.dumps(jwk_data)
    if jwk_data.get("kty") == "RSA":
        return RSAAlgorithm.from_jwk(raw)
    if jwk_data.get("kty") == "EC":
        return ECAlgorithm.from_jwk(raw)
    raise RuntimeError(f"Unsupported JWK kty: {jwk_data.get('kty')}")


async def get_oauth_token() -> str:
    now = int(time.time())
    if _token_cache["token"] and now < _token_cache["expires_at"] - 60:
        return _token_cache["token"]
    if not CLIENT_ID:
        raise RuntimeError("OKTA_CLIENT_ID is not set")

    jwk_data = load_private_jwk()
    key = private_key_from_jwk(jwk_data)
    alg = jwk_data.get("alg") or ("RS256" if jwk_data.get("kty") == "RSA" else "ES256")
    kid = jwk_data.get("kid")
    token_url = f"{OKTA_DOMAIN}/oauth2/v1/token"
    claims = {
        "aud": token_url,
        "iss": CLIENT_ID,
        "sub": CLIENT_ID,
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
    }
    assertion = jwt.encode(claims, key, algorithm=alg, headers={"kid": kid} if kid else None)
    data = {
        "grant_type": "client_credentials",
        "scope": SCOPES,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
    }
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(token_url, data=data, headers={"Accept": "application/json"})
    if r.status_code != 200:
        raise RuntimeError(f"OAuth token request failed HTTP {r.status_code}: {r.text}")

    payload = r.json()
    _token_cache["token"] = payload["access_token"]
    _token_cache["expires_at"] = now + int(payload.get("expires_in", 3600))
    return payload["access_token"]


async def okta_headers() -> dict[str, str]:
    if AUTH_MODE == "ssws":
        if not SSWS_TOKEN:
            raise RuntimeError("OKTA_TOKEN is not set")
        return {"Authorization": f"SSWS {SSWS_TOKEN}", "Accept": "application/json"}
    if AUTH_MODE == "oauth":
        return {"Authorization": f"Bearer {await get_oauth_token()}", "Accept": "application/json"}
    raise RuntimeError("OKTA_AUTH_MODE must be oauth or ssws")


@dataclass
class OktaResult:
    status_code: int
    data: Any
    headers: dict[str, str]


async def okta_request(method: str, path: str, json_body: Any | None = None) -> OktaResult:
    headers = await okta_headers()
    if json_body is not None:
        headers["Content-Type"] = "application/json"

    for attempt in range(API_RETRY_429 + 1):
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.request(method, f"{OKTA_DOMAIN}{path}", headers=headers, json=json_body)
        if r.status_code != 429 or attempt >= API_RETRY_429:
            break
        reset = r.headers.get("x-rate-limit-reset")
        wait = 2.0
        if reset and reset.isdigit():
            wait = max(1.0, min(30.0, int(reset) - int(time.time()) + 1))
        await asyncio.sleep(wait)

    try:
        data = r.json() if r.content else {}
    except Exception:
        data = {"raw": r.text}
    return OktaResult(r.status_code, data, dict(r.headers))


def error_text(result: OktaResult) -> str:
    if isinstance(result.data, dict):
        return result.data.get("errorSummary", str(result.data))
    return str(result.data)


async def lookup_user(login: str) -> dict[str, Any]:
    result = await okta_request("GET", f"/api/v1/users/{quote(login, safe='')}")
    if result.status_code != 200:
        return {"login_input": login, "ok": False, "http": result.status_code, "error": error_text(result)}

    return user_summary(result.data, login_input=login)


def user_summary(user: dict[str, Any], login_input: str | None = None) -> dict[str, Any]:
    profile = user.get("profile", {})
    links = user.get("_links", {})
    status = user.get("status")
    can_activate = "activate" in links
    can_reactivate = "reactivate" in links
    activation_action = "activate" if status == "STAGED" else "reactivate" if status == "PROVISIONED" else None
    return {
        "login_input": login_input or profile.get("login"),
        "ok": True,
        "id": user.get("id"),
        "status": status,
        "login": profile.get("login"),
        "email": profile.get("email"),
        "firstName": profile.get("firstName"),
        "lastName": profile.get("lastName"),
        "organization": profile.get("organization"),
        "department": profile.get("department"),
        "can_activate": can_activate,
        "can_reactivate": can_reactivate,
        "activation_action": activation_action,
    }


def next_page_path(link_header: str) -> str | None:
    match = re.search(r'<([^>]+)>;\s*rel="next"', link_header)
    if not match:
        return None
    parsed = urlsplit(match.group(1))
    return f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path


async def list_users(path: str) -> list[dict[str, Any]]:
    users: list[dict[str, Any]] = []
    while path:
        result = await okta_request("GET", path)
        if result.status_code != 200:
            raise HTTPException(result.status_code, error_text(result))
        users.extend(result.data)
        path = next_page_path(result.headers.get("link", ""))
    return users


async def list_users_with_status(status: str) -> list[dict[str, Any]]:
    return await list_users(f'/api/v1/users?filter=status%20eq%20%22{quote(status, safe="")}%22&limit=200')


async def list_user_directory() -> list[dict[str, Any]]:
    users = await list_users("/api/v1/users?limit=200")
    return sorted((user_summary(user) for user in users), key=lambda user: (user["login"] or "").lower())


async def list_pending_activation_users() -> tuple[list[dict[str, Any]], int]:
    staged, provisioned = await asyncio.gather(
        list_users_with_status("STAGED"),
        list_users_with_status("PROVISIONED"),
    )
    users = [user_summary(user) for user in staged + provisioned]
    cooling_down = users_in_activation_cooldown([user["id"] for user in users if user.get("id")])
    visible = [user for user in users if user.get("id") not in cooling_down]
    return sorted(visible, key=lambda user: (user["status"], (user["login"] or "").lower())), len(cooling_down)


async def list_groups() -> list[dict[str, Any]]:
    result = await okta_request("GET", "/api/v1/groups?limit=200")
    if result.status_code != 200:
        raise HTTPException(result.status_code, error_text(result))
    groups = []
    for g in result.data:
        profile = g.get("profile", {})
        groups.append({
            "id": g.get("id"),
            "name": profile.get("name", ""),
            "description": profile.get("description", ""),
            "type": g.get("type", ""),
        })
    return sorted(groups, key=lambda x: x["name"].lower())


def parse_group_names(value: str | None) -> list[str]:
    if not value:
        return []
    normalized = value.replace("|", ";")
    return [x.strip() for x in normalized.split(";") if x.strip()]


def normalize_create_row(row: dict[str, str]) -> dict[str, Any]:
    return {
        "firstName": (row.get("firstName") or "").strip(),
        "lastName": (row.get("lastName") or "").strip(),
        "login": (row.get("login") or "").strip(),
        "email": (row.get("email") or "").strip(),
        "department": (row.get("department") or "").strip(),
        "groups": parse_group_names(row.get("groups")),
    }


def validate_create_row(row: dict[str, Any]) -> list[str]:
    errors = []
    for field in ("firstName", "lastName", "login", "email"):
        if not row.get(field):
            errors.append(f"missing {field}")
    if row.get("login") and "@" not in row["login"]:
        errors.append("login does not look like an email-style login")
    if row.get("email") and "@" not in row["email"]:
        errors.append("email is invalid")
    return errors


async def resolve_group_names(names: list[str], all_groups: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    by_name = {g["name"].lower(): g["id"] for g in all_groups if g.get("name") and g.get("id")}
    ids, missing = [], []
    for name in names:
        gid = by_name.get(name.lower())
        if gid:
            ids.append(gid)
        else:
            missing.append(name)
    return ids, missing


class LookupRequest(BaseModel):
    login: str


class BulkSendRequest(BaseModel):
    logins: list[str]
    batch_size: int = 20
    confirmation: str


class CreateUserRow(BaseModel):
    firstName: str
    lastName: str
    login: str
    email: str
    department: str = ""
    groups: list[str] = []


class BulkCreateRequest(BaseModel):
    rows: list[CreateUserRow]
    global_group_ids: list[str] = []
    confirmation: str


@app.get("/", response_class=HTMLResponse)
async def home(request: Request, _: bool = Depends(require_web_auth)):
    return templates.TemplateResponse(request=request, name="index.html", context={"auth_mode": AUTH_MODE, "domain": OKTA_DOMAIN})


@app.get("/api/health")
async def health(_: bool = Depends(require_web_auth)):
    return {"ok": True, "version": "0.3.0", "auth_mode": AUTH_MODE, "domain_configured": bool(OKTA_DOMAIN)}


@app.get("/api/groups")
async def api_groups(_: bool = Depends(require_web_auth)):
    return {"groups": await list_groups()}


@app.get("/api/activation/pending")
async def pending_activation_users(_: bool = Depends(require_web_auth)):
    users, cooling_down = await list_pending_activation_users()
    return {
        "summary": {
            "total": len(users),
            "STAGED": sum(user["status"] == "STAGED" for user in users),
            "PROVISIONED": sum(user["status"] == "PROVISIONED" for user in users),
            "eligible": sum(user["activation_action"] is not None for user in users),
            "cooling_down": cooling_down,
            "cooldown_hours": ACTIVATION_COOLDOWN_HOURS,
        },
        "users": users,
    }


@app.get("/api/activation/cooldown")
async def activation_cooldown_users(_: bool = Depends(require_web_auth)):
    records = activation_cooldown_records()
    users_by_id = {user["id"]: user for user in await list_user_directory() if user.get("id")}
    users = []
    for record in records:
        current = users_by_id.get(record["id"])
        if current:
            users.append({**current, "last_sent_at": record["last_sent_at"]})
        else:
            users.append({"id": record["id"], "login": record["login"], "status": "NOT_FOUND", "last_sent_at": record["last_sent_at"]})
    return {
        "summary": {
            "total": len(users),
            "ACTIVE": sum(user.get("status") == "ACTIVE" for user in users),
            "PENDING": sum(user.get("status") in {"STAGED", "PROVISIONED"} for user in users),
            "cooldown_hours": ACTIVATION_COOLDOWN_HOURS,
        },
        "users": users,
    }


@app.get("/api/users/directory")
async def user_directory(_: bool = Depends(require_web_auth)):
    users = await list_user_directory()
    return {"count": len(users), "users": users}


@app.post("/api/lookup")
async def api_lookup(payload: LookupRequest, _: bool = Depends(require_web_auth)):
    login = payload.login.strip()
    if not login:
        raise HTTPException(400, "login is required")
    try:
        return await lookup_user(login)
    except Exception as e:
        raise HTTPException(500, str(e)) from e


@app.post("/api/bulk/preview")
async def bulk_preview(file: UploadFile = File(...), _: bool = Depends(require_web_auth)):
    raw = await file.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(400, "CSV must be UTF-8/UTF-8-BOM")

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or "login" not in [h.strip() for h in reader.fieldnames]:
        raise HTTPException(400, "CSV must contain a 'login' column")

    rows = []
    for row in reader:
        login = (row.get("login") or "").strip()
        if login:
            rows.append(await lookup_user(login))

    summary = {"total": len(rows), "PROVISIONED": 0, "ACTIVE": 0, "OTHER": 0, "ERROR": 0}
    for row in rows:
        if not row.get("ok"):
            summary["ERROR"] += 1
        elif row.get("status") == "PROVISIONED":
            summary["PROVISIONED"] += 1
        elif row.get("status") == "ACTIVE":
            summary["ACTIVE"] += 1
        else:
            summary["OTHER"] += 1
    return {"summary": summary, "rows": rows}


@app.post("/api/bulk/send")
async def bulk_send(payload: BulkSendRequest, _: bool = Depends(require_web_auth)):
    if payload.confirmation != "SEND":
        raise HTTPException(400, 'confirmation must be exactly "SEND"')
    if not 1 <= payload.batch_size <= MAX_ACTIVATION_BATCH:
        raise HTTPException(400, f"batch_size must be between 1 and {MAX_ACTIVATION_BATCH}")
    if len(payload.logins) > payload.batch_size:
        raise HTTPException(400, "Too many users in one send request; choose a smaller batch")

    logins = [login.strip() for login in payload.logins if login.strip()]
    job_id = str(uuid.uuid4())
    activation_jobs[job_id] = {"id": job_id, "status": "queued", "logins": logins, "results": [], "created_at": int(time.time())}
    asyncio.create_task(process_activation_job(job_id))
    return {"job_id": job_id, "count": len(logins), "status": "queued"}


async def send_activation_for_login(login: str) -> dict[str, Any]:
    try:
        user = await lookup_user(login)
    except Exception as exc:
        return {"login_input": login, "result": "LOOKUP_ERROR", "error": str(exc)}
    if not user.get("ok"):
        return {**user, "result": "LOOKUP_ERROR"}
    action = user.get("activation_action")
    if not action:
        return {**user, "result": f"SKIPPED_{user.get('status')}"}
    remaining = activation_cooldown_remaining(user.get("id"))
    if remaining:
        return {**user, "result": "SKIPPED_COOLDOWN", "cooldown_minutes_remaining": (remaining + 59) // 60}
    try:
        sent = await okta_request("POST", f"/api/v1/users/{quote(user['id'], safe='')}/lifecycle/{action}?sendEmail=true")
    except Exception as exc:
        return {**user, "result": "SEND_ERROR", "error": str(exc)}
    if sent.status_code != 200:
        return {**user, "result": "SEND_ERROR", "http": sent.status_code, "error": error_text(sent)}
    try:
        record_activation_sent(user["id"], user.get("login") or login)
    except Exception as exc:
        return {**user, "result": "SENT_COOLDOWN_RECORD_ERROR", "http": 200, "error": str(exc)}
    return {**user, "result": "SENT", "http": 200}


async def process_activation_job(job_id: str) -> None:
    job = activation_jobs[job_id]
    job["status"] = "running"
    try:
        for index, login in enumerate(job["logins"]):
            job["results"].append(await send_activation_for_login(login))
            if index < len(job["logins"]) - 1:
                await asyncio.sleep(SEND_DELAY)
        job["status"] = "completed"
    except Exception as exc:
        job["status"] = "failed"
        job["error"] = str(exc)


@app.get("/api/bulk/send/{job_id}")
async def bulk_send_status(job_id: str, _: bool = Depends(require_web_auth)):
    job = activation_jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Send job not found; it may have been interrupted by an app restart")
    return {
        "job_id": job["id"],
        "status": job["status"],
        "count": len(job["logins"]),
        "processed": len(job["results"]),
        "results": job["results"],
        "error": job.get("error", ""),
    }


@app.post("/api/create/preview")
async def create_preview(
    file: UploadFile = File(...),
    global_group_ids: str = Form("[]"),
    _: bool = Depends(require_web_auth),
):
    try:
        selected_group_ids = json.loads(global_group_ids)
        if not isinstance(selected_group_ids, list):
            raise ValueError
    except Exception as e:
        raise HTTPException(400, "global_group_ids must be a JSON array") from e

    raw = await file.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(400, "CSV must be UTF-8/UTF-8-BOM")
    reader = csv.DictReader(io.StringIO(text))
    required = {"firstName", "lastName", "login", "email"}
    fields = {h.strip() for h in (reader.fieldnames or [])}
    if not required.issubset(fields):
        raise HTTPException(400, "CSV must contain firstName,lastName,login,email")

    all_groups = await list_groups()
    group_by_id = {g["id"]: g for g in all_groups}
    bad_global = [gid for gid in selected_group_ids if gid not in group_by_id]
    if bad_global:
        raise HTTPException(400, f"Unknown selected group IDs: {', '.join(bad_global)}")

    rows = []
    seen_logins: set[str] = set()
    for source in reader:
        row = normalize_create_row(source)
        if not any([row["firstName"], row["lastName"], row["login"], row["email"]]):
            continue
        errors = validate_create_row(row)
        key = row["login"].lower()
        if key and key in seen_logins:
            errors.append("duplicate login in CSV")
        if key:
            seen_logins.add(key)

        csv_group_ids, missing_groups = await resolve_group_names(row["groups"], all_groups)
        if missing_groups:
            errors.append("group not found: " + ", ".join(missing_groups))
        merged_group_ids = list(dict.fromkeys(selected_group_ids + csv_group_ids))
        merged_group_names = [group_by_id[gid]["name"] for gid in merged_group_ids if gid in group_by_id]

        exists = None
        existing_status = None
        if not errors:
            existing = await lookup_user(row["login"])
            if existing.get("ok"):
                exists = True
                existing_status = existing.get("status")
            elif existing.get("http") == 404:
                exists = False
            else:
                errors.append(f"lookup failed HTTP {existing.get('http')}: {existing.get('error')}")

        rows.append({
            **row,
            "group_ids": merged_group_ids,
            "group_names": merged_group_names,
            "exists": exists,
            "existing_status": existing_status,
            "valid": not errors,
            "errors": errors,
        })

    summary = {"total": len(rows), "NEW": 0, "EXISTS": 0, "INVALID": 0}
    for row in rows:
        if not row["valid"]:
            summary["INVALID"] += 1
        elif row["exists"]:
            summary["EXISTS"] += 1
        else:
            summary["NEW"] += 1
    return {"summary": summary, "rows": rows, "selected_groups": [group_by_id[gid] for gid in selected_group_ids]}


@app.post("/api/create/send")
async def create_send(payload: BulkCreateRequest, _: bool = Depends(require_web_auth)):
    if payload.confirmation != "CREATE":
        raise HTTPException(400, 'confirmation must be exactly "CREATE"')

    all_groups = await list_groups()
    valid_group_ids = {g["id"] for g in all_groups}
    global_group_ids = [gid for gid in payload.global_group_ids if gid in valid_group_ids]
    results = []

    for idx, model in enumerate(payload.rows):
        row = model.model_dump()
        errors = validate_create_row(row)
        if errors:
            results.append({**row, "result": "INVALID", "error": "; ".join(errors)})
            continue

        existing = await lookup_user(row["login"])
        if existing.get("ok"):
            results.append({**row, "id": existing.get("id"), "status": existing.get("status"), "result": "SKIPPED_EXISTS"})
            continue
        if existing.get("http") != 404:
            results.append({**row, "result": "LOOKUP_ERROR", "http": existing.get("http"), "error": existing.get("error")})
            continue

        csv_group_ids, missing_names = await resolve_group_names(row.get("groups", []), all_groups)
        if missing_names:
            results.append({**row, "result": "INVALID_GROUP", "error": "group not found: " + ", ".join(missing_names)})
            continue
        group_ids = list(dict.fromkeys(global_group_ids + csv_group_ids))

        profile = {
            "firstName": row["firstName"],
            "lastName": row["lastName"],
            "login": row["login"],
            "email": row["email"],
        }
        if row.get("department"):
            profile["department"] = row["department"]

        created = await okta_request("POST", "/api/v1/users?activate=false", {"profile": profile})
        if created.status_code not in (200, 201):
            results.append({**row, "result": "CREATE_ERROR", "http": created.status_code, "error": error_text(created)})
            continue

        uid = created.data.get("id")
        group_results = []
        group_failed = False
        for gid in group_ids:
            if gid not in valid_group_ids:
                group_results.append({"group_id": gid, "ok": False, "http": 400, "error": "unknown group"})
                group_failed = True
                continue
            added = await okta_request("PUT", f"/api/v1/groups/{quote(gid, safe='')}/users/{quote(uid, safe='')}")
            ok = added.status_code in (200, 204)
            group_results.append({"group_id": gid, "ok": ok, "http": added.status_code, "error": "" if ok else error_text(added)})
            group_failed = group_failed or not ok

        if group_failed:
            result = "PARTIAL_GROUP_ERROR"
        else:
            result = "CREATED"

        results.append({
            **row,
            "id": uid,
            "status": created.data.get("status"),
            "result": result,
            "group_results": group_results,
            "activation": "NOT_SENT",
            "error": "",
        })
        if idx < len(payload.rows) - 1:
            await asyncio.sleep(SEND_DELAY)

    return {"count": len(results), "results": results}
