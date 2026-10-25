"""Print a bcrypt hash for CONSOLE_ADMIN_PASSWORD_HASH. The password is not stored."""

import getpass

import bcrypt


def main() -> None:
    password = getpass.getpass("Console admin password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        raise SystemExit("Passwords did not match.")
    if not password:
        raise SystemExit("Password is empty.")
    if len(password.encode()) > 72:
        raise SystemExit("bcrypt only uses the first 72 bytes. Choose a shorter password.")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    print(hashed.decode())


if __name__ == "__main__":
    main()
