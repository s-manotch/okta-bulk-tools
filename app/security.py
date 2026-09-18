import base64
import bcrypt


def verify_password_b64(password: str, encoded_record: str) -> bool:
    try:
        password_hash = base64.b64decode(encoded_record.encode("ascii"), validate=True)
        return bcrypt.checkpw(password.encode("utf-8"), password_hash)
    except (ValueError, TypeError):
        return False
