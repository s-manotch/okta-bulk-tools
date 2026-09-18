import argparse
import getpass

from app.security import hash_password_b64


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate secure values for the app configuration")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("hash-password", help="create WEB_PASSWORD_HASH_B64")
    args = parser.parse_args()

    if args.command == "hash-password":
        password = getpass.getpass("Web password: ")
        confirmation = getpass.getpass("Confirm web password: ")
        if not password:
            raise SystemExit("Password must not be empty")
        if password != confirmation:
            raise SystemExit("Passwords do not match")
        print(f"WEB_PASSWORD_HASH_B64={hash_password_b64(password)}")


if __name__ == "__main__":
    main()
