"""One-time Google OAuth2 authorization (run manually, NOT part of the API).

Opens a browser for you to log in with a Desktop-app OAuth2 client, then
saves a refresh token to the file named by GOOGLE_TOKEN_FILE in .env.

Usage:
    python scripts/authorize_google.py

Requires GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env. Requests both
Calendar and Gmail scopes so one token serves both services.
"""
import json
import os
import sys

# Allow running as a plain script from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from google_auth_oauthlib.flow import InstalledAppFlow

from app.config import settings
from app.services.google_auth import SCOPES


def main() -> int:
    if not settings.google_client_id or not settings.google_client_secret:
        print(
            "ERROR: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set in .env "
            "(Desktop app credentials from Google Cloud Console)."
        )
        return 1

    client_config = {
        "installed": {
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["http://localhost"],
        }
    }

    flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
    creds = flow.run_local_server(port=0, prompt="consent", access_type="offline")

    token_file = settings.google_token_file
    os.makedirs(os.path.dirname(os.path.abspath(token_file)), exist_ok=True)
    # L10 fix: OAuth credentials must not be group/world-readable.
    _fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(_fd, "w", encoding="utf-8") as fh:
        fh.write(creds.to_json())

    print(f"Success. Refresh token saved to: {os.path.abspath(token_file)}")
    print("This file is git-ignored. The API services will auto-refresh it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
