import os
import json
import requests
from typing import Tuple, Optional

from dotenv import load_dotenv

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build

TOKENINFO_URL = "https://www.googleapis.com/oauth2/v1/tokeninfo"
TOKEN_URL = "https://oauth2.googleapis.com/token"
OAUTH_SCOPE = ["https://www.googleapis.com/auth/drive"]

# Load environment variables from .env file
load_dotenv()

def _update_env_var(key: str, value: str):
    """Optional convenience: keep ACCESS_TOKEN in .env synced."""
    env_path = ".env"
    lines = []
    found = False
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith(f"{key}="):
                    lines.append(f"{key}={value}\n")
                    found = True
                else:
                    lines.append(line)
    if not found:
        lines.append(f"{key}={value}\n")
    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

def _validate_token(access_token: str) -> bool:
    """Return True if token looks valid; False if invalid/expired."""
    if not access_token:
        return False
    try:
        r = requests.post(f"{TOKENINFO_URL}?access_token={access_token}", timeout=10)
        data = r.json() if r.text else {}
        # tokeninfo returns 200 for valid; includes 'error' for invalid
        return "error" not in data
    except Exception:
        # If tokeninfo has issues, be conservative and force refresh
        return False

def _refresh_token(client_id: str, client_secret: str, refresh_token: str) -> Optional[str]:
    """Use refresh_token to obtain a new access_token."""
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(TOKEN_URL, data=payload, headers=headers, timeout=15)
    data = r.json()
    return data.get("access_token")

def _get_creds_from_env() -> Optional[dict]:
    cid = os.getenv("CLIENT_ID")
    csec = os.getenv("CLIENT_SECRET")
    rtok = os.getenv("REFRESH_TOKEN")
    atok = os.getenv("ACCESS_TOKEN")
    if cid and csec and rtok:
        return {
            "client_id": cid,
            "client_secret": csec,
            "refresh_token": rtok,
            "access_token": atok or "",
        }
    return None

def check_token(sync_env: bool = True) -> str:
    """
    Returns a valid access_token.
    - Gets credentials from .env file
    - Validates access token; refreshes if needed
    - Saves refreshed token back to .env
    """
    row = _get_creds_from_env()
    if not row:
        raise RuntimeError("No credentials found in .env file")

    access_token = row.get("access_token") or ""
    client_id = row["client_id"]
    client_secret = row["client_secret"]
    refresh_token = row["refresh_token"]

    if not _validate_token(access_token):
        new_token = _refresh_token(client_id, client_secret, refresh_token)
        if not new_token:
            raise RuntimeError("Failed to refresh access token; check client/refresh credentials.")
        access_token = new_token

        # Token refreshed successfully

        if sync_env:
            _update_env_var("ACCESS_TOKEN", access_token)

    return access_token

def get_drive_service(sync_env: bool = True):
    """
    Returns (drive_service, access_token) ready for use.
    The service is built with a Credentials object that can auto-refresh on demand.
    """
    # Ensure we have a fresh token first
    access_token = check_token(sync_env=sync_env)

    # Load creds to build a proper Credentials object with refresh capability
    row = _get_creds_from_env()
    if not row:
        raise RuntimeError("No credentials found in .env file to build Drive service.")

    creds = Credentials(
        token=access_token,
        refresh_token=row["refresh_token"],
        client_id=row["client_id"],
        client_secret=row["client_secret"],
        token_uri=TOKEN_URL,
        scopes=OAUTH_SCOPE,
    )

    # Optional: proactively refresh if expired (rare just after check_token)
    if not creds.valid:
        try:
            creds.refresh(GoogleRequest())
            access_token = creds.token
            if sync_env:
                _update_env_var("ACCESS_TOKEN", access_token)
            # Token refreshed successfully
        except Exception as e:
            raise RuntimeError(f"Credential refresh failed: {e}")

    drive = build("drive", "v3", credentials=creds, cache_discovery=False)
    return drive, access_token

# Quick test
if __name__ == "__main__":
    svc, tok = get_drive_service()
    print("Drive client ready. Access token (shortened):", (tok[:20] + "...") if tok else "None")
    # Example: list 5 files (also proves auth works)
    resp = svc.files().list(pageSize=5, fields="files(id,name)", supportsAllDrives=True, includeItemsFromAllDrives=True).execute()
    for f in resp.get("files", []):
        print(f"- {f['name']} ({f['id']})")
