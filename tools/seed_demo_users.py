#!/usr/bin/env python3
"""Create or repair demo accounts used for manual UI checks.

The Docker client containers mount repo-local ``1.png`` at ``/root/1.png`` so
the image is easy to pick from the avatar upload dialog in VNC.  Older Compose
files did not mount it, so the script still falls back to ``docker cp`` when the
file is not already present inside a running client container.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path


USERS = (
    ("user123", "123@gmail.com", "123456"),
    ("user234", "234@gmail.com", "123456"),
    ("user345", "345@gmail.com", "123456"),
)


def _dotenv() -> dict[str, str]:
    out: dict[str, str] = {}
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return out
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def _sql_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _client_hash(password: str, email: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        email.lower().encode("utf-8"),
        100_000,
        dklen=32,
    ).hex()


def _server_hash(client_hash: str) -> str:
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        client_hash.encode("utf-8"),
        salt,
        600_000,
        dklen=32,
    )
    return f"{salt.hex()}:{derived.hex()}"


def _mysql(sql: str) -> None:
    env = _dotenv()
    root_pw = os.environ.get("MYSQL_ROOT_PASSWORD") or env.get(
        "MYSQL_ROOT_PASSWORD", "rootpass")
    subprocess.run(
        [
            "docker", "exec", "chat-db", "mysql",
            "-uroot", f"-p{root_pw}", "chatdb", "-e", sql,
        ],
        check=True,
    )


def main() -> None:
    statements: list[str] = []
    for username, email, password in USERS:
        stored = _server_hash(_client_hash(password, email))
        username_sql = _sql_escape(username)
        email_sql = _sql_escape(email)
        stored_sql = _sql_escape(stored)
        statements.append(
            "INSERT INTO users(username,email,password_hash,display_name) "
            f"VALUES('{username_sql}','{email_sql}','{stored_sql}','{username_sql}') "
            "ON DUPLICATE KEY UPDATE "
            f"email='{email_sql}', password_hash='{stored_sql}', "
            f"display_name='{username_sql}'"
        )
    _mysql(";".join(statements) + ";")
    for username, email, _ in USERS:
        print(f"seeded {email} / 123456 as {username}")
    avatar = Path(__file__).resolve().parents[1] / "1.png"
    if avatar.is_file():
        for container in ("chat-client1", "chat-client2"):
            try:
                present = subprocess.run(
                    ["docker", "exec", container, "test", "-f", "/root/1.png"],
                    check=False,
                )
                if present.returncode == 0:
                    print(f"1.png available in {container}:/root/1.png")
                    continue
                subprocess.run(
                    ["docker", "cp", str(avatar), f"{container}:/root/1.png"],
                    check=True,
                )
                print(f"copied 1.png to {container}:/root/1.png")
            except subprocess.CalledProcessError:
                print(f"warning: could not copy 1.png to {container}")


if __name__ == "__main__":
    main()
