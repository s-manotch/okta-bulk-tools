#!/usr/bin/env python3
import base64
import getpass

import bcrypt


password = getpass.getpass("Web password: ")
confirm = getpass.getpass("Confirm password: ")
if password != confirm:
    raise SystemExit("Passwords do not match")
if len(password) < 12:
    raise SystemExit("Use at least 12 characters")

password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
print(f"WEB_PASSWORD_HASH_B64={base64.b64encode(password_hash).decode('ascii')}")
