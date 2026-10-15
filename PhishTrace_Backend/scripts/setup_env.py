"""Create a local .env file with a newly generated, high-entropy secret key.

This script never overwrites an existing .env file. The resulting file is
ignored by Git and should not be shared or committed.
"""
from __future__ import annotations

import secrets
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = PROJECT_ROOT / ".env"


def main() -> int:
    if ENV_PATH.exists():
        print(f"Refusing to overwrite existing file: {ENV_PATH}")
        print("Keep the existing key, or back up and rotate it deliberately.")
        return 1

    secret = secrets.token_urlsafe(48)
    contents = f'''# Local PhishTrace configuration. Do not commit or share this file.\nPHISHTRACE_ENV=development\nPHISHTRACE_SECRET_KEY={secret}\nPHISHTRACE_HOST=127.0.0.1\nPHISHTRACE_PORT=5055\nPHISHTRACE_DEBUG=false\nPHISHTRACE_MAX_URL_LENGTH=2048\nPHISHTRACE_STORE_SCAN_HISTORY=false\nPHISHTRACE_DATABASE_PATH=instance/phishtrace.sqlite3\n'''

    # Exclusive creation avoids overwriting a file created concurrently.
    with ENV_PATH.open("x", encoding="utf-8") as file:
        file.write(contents)

    try:
        ENV_PATH.chmod(0o600)
    except OSError:
        # chmod semantics vary by platform; .env is still ignored by Git.
        pass

    print(f"Created {ENV_PATH}")
    print("Generated a fresh secret key and restricted file permissions where supported.")
    print("The .env file is excluded by .gitignore. Do not paste the key into chats or GitHub.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
