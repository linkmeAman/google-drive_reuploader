#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Drive Video Reuploader (No-Local-Disk Streaming)

WHAT IT DOES
------------
This script can work in two modes:

1. Single File Mode:
   Given a Google Drive file ID or /file/d/<id>/preview URL, it:
   - Checks if the video is previewable in Drive
   - Re-uploads using a Drive->Drive streaming pipeline if needed
   - Polls until the new file becomes previewable
   - Moves/archives the original file

2. Folder Scan Mode (--scan-folders):
   - Scans all folders defined in .env (DRIVE_FOLDER_* entries)
   - Identifies videos with playback issues
   - With --auto-fix, automatically re-uploads problematic videos
   - Keeps files in their original folders
   - Provides a summary of all issues found

WHY THIS EXISTS
---------------
- Some uploads end up with wrong MIME or codecs that Drive doesn't immediately
  process for web preview. A fresh upload (especially with `video/mp4`) often
  kicks Drive's transcoder into gear.
- `files.copy` usually doesn't re-transcode; a real re-upload is more reliable.

REQUIREMENTS
------------
Python 3.9+
pip install:
  google-api-python-client
  google-auth
  google-auth-oauthlib
  requests
  python-dotenv   (optional, only if you want .env support)

CREDENTIALS
-----------
Use ONE of:
- Service Account: set env GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json
- OAuth Installed App: place 'credentials.json' in the working dir (client ID/secret).
  We'll auto-create/refresh 'token.json' after first consent.

Scopes: https://www.googleapis.com/auth/drive

USAGE EXAMPLES
--------------
# Single File Mode:
python drive_video_reuploader.py \
  --file "https://drive.google.com/file/d/1HiB7retertNPs-et-a/preview" \
  --temp-folder TEMP_FOLDER_ID \
  --final-folder FINAL_FOLDER_ID \
  --archive-original=false

# With MIME override and archiving:
python drive_video_reuploader.py \
  --file 1HiB7retertNPs-et-a \
  --temp-folder TEMP_FOLDER_ID \
  --final-folder FINAL_FOLDER_ID \
  --mime-override video/mp4 \
  --archive-original=true \
  --archive-folder ARCHIVE_FOLDER_ID \
  --retry-count 10 \
  --retry-delay-seconds 45

# Folder Scan Mode:
# Just scan and report issues:
python drive_video_reuploader.py --scan-folders

# Scan and automatically fix issues:
python drive_video_reuploader.py --scan-folders --auto-fix

NOTES
-----
- Memory bounded by CHUNK_SIZE (default 16 MB). No video writes to disk.
- Small local state file (JSON) saved as '.drive_reupload_state.json' (tiny).
- Shared Drives supported via supportsAllDrives/includeItemsFromAllDrives.

example invocations:
python drive_video_reuploader.py --file "1J2nPdVKEV-eXPg1YVb75tJ6CCqif2OUL" --temp-folder "14JYr4ugdFnp-wAGnC32mkTh1DyLeYMUv" --final-folder "14JYr4ugdFnp-wAGnC32mkTh1DyLeYMUv" --archive-original=true --archive-folder "14JYr4ugdFnp-wAGnC32mkTh1DyLeYMUv" --mime-override "video/mp4" --retry-count 10
"""

import argparse
import json
import math
import os
import re
import sys
import time
import logging
from datetime import datetime
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta

import requests
from requests import Response

from google.oauth2 import service_account
from google.auth.transport.requests import Request, AuthorizedSession
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

STATE_FILE = ".drive_reupload_state.json"
SCOPES = ['https://www.googleapis.com/auth/drive']

CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB; keep <=64MB peak RAM

PROCESSING_BANNERS = [
    "It's taking longer than expected to process this video file for playback",
    "It's taking longer than expected to process this video",
    "This video file is unplayable",
    "This video file has an invalid format and is not supported by Drive",
    "Please try again later, or contact support if this issue persists",
    "If you trust the file, you can download it for offline playback"
]


def setup_auth() -> Tuple[AuthorizedSession, object]:
    """
    Returns (AuthorizedSession, DriveService).
    Uses the access_token.py authentication system.
    """
    from access_token import get_drive_service, Credentials, GoogleRequest, _get_creds_from_env, TOKEN_URL
    
    # Get drive service and token using existing auth system
    drive, access_token = get_drive_service(sync_env=True)
    
    # Create credentials for authorized session
    row = _get_creds_from_env()
    if not row:
        raise RuntimeError("No credentials found in .env file. Please check your .env configuration.")
        
    creds = Credentials(
        token=access_token,
        refresh_token=row["refresh_token"],
        client_id=row["client_id"],
        client_secret=row["client_secret"],
        token_uri=TOKEN_URL,
        scopes=SCOPES,
    )
    
    authed_session = AuthorizedSession(creds)
    return authed_session, drive


def parse_file_id(s: str) -> str:
    m = re.search(r"/file/d/([a-zA-Z0-9_-]+)", s)
    if m:
        return m.group(1)
    return s.strip()


def get_file_metadata(drive, file_id: str) -> Dict:
    fields = "id,name,mimeType,size,parents,thumbnailLink,videoMediaMetadata,driveId,createdTime,modifiedTime,md5Checksum"
    return drive.files().get(
        fileId=file_id,
        fields=fields,
        supportsAllDrives=True
    ).execute()


def is_preview_ready(authed_session: AuthorizedSession, meta: Dict) -> Tuple[bool, str]:
    """
    Returns (ready:bool, reason:str)
    Ready if both thumbnailLink and videoMediaMetadata exist (metadata says processed)
    OR HTML probe doesn't contain 'processing' banners and returns a valid viewer page.
    """
    if meta.get("thumbnailLink") and meta.get("videoMediaMetadata") and meta.get("videoMediaMetadata", {}).get("processingStatus") == "PROCESSED":
        return True, "metadata"

    # HTML probe
    preview_url = f"https://drive.google.com/file/d/{meta['id']}/preview"
    resp = authed_session.get(preview_url)
    if resp.status_code == 200:
        html = resp.text or ""
        if any(b in html for b in PROCESSING_BANNERS):
            return False, "html:processing_banner"
        # More thorough check: ensure no processing banners and viewer is present
        if ("drive-viewer" in html or "video" in html) and not any(b in html for b in PROCESSING_BANNERS):
            return True, "html:viewer_detected"
        return False, "html:no_viewer"
    if resp.status_code in (403, 404):
        return False, f"html:perm_or_notfound({resp.status_code})"
    return False, f"html:status_{resp.status_code}"


def audit_upload_health(meta: Dict) -> Dict:
    name = meta.get("name", "")
    ext = os.path.splitext(name)[1].lower()
    mime = meta.get("mimeType", "")
    bad_mime = (not mime.startswith("video/")) or (mime == "application/octet-stream")
    return {
        "name": name,
        "ext": ext,
        "mimeType": mime,
        "badMime": bad_mime,
        "hasVideoMeta": bool(meta.get("videoMediaMetadata")),
    }


def create_resumable_session(
    authed_session: AuthorizedSession,
    name: str,
    mime_type: str,
    file_id: str = None,
    parent_folder_id: str = None
) -> str:
    """
    Initiate a resumable upload session for creating new file or updating existing file.
    Returns the session URL (Location header).
    """
    if file_id:
        # Update existing file
        url = f"https://www.googleapis.com/upload/drive/v3/files/{file_id}?uploadType=resumable&supportsAllDrives=true"
    else:
        # Create new file
        url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&supportsAllDrives=true"
    
    headers = {
        "X-Upload-Content-Type": mime_type,
        "Content-Type": "application/json; charset=UTF-8",
    }
    
    body = {
        "name": name,
        "mimeType": mime_type,
    }
    
    if parent_folder_id:
        body["parents"] = [parent_folder_id]
    
    # Use PATCH for updates, POST for new files
    if file_id:
        resp = authed_session.patch(url, headers=headers, json=body)
    else:
        resp = authed_session.post(url, headers=headers, json=body)
        
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Failed to create resumable session: {resp.status_code} {resp.text}")
    
    upload_url = resp.headers.get("Location")
    if not upload_url:
        raise RuntimeError("No Location header returned for resumable session")
    return upload_url


def stream_copy_drive_to_resumable(
    authed_session: AuthorizedSession,
    source_file_id: str,
    upload_url: str,
    total_size: Optional[int],
    chunk_size: int = CHUNK_SIZE,
    retry_max: int = 5,
) -> Dict:
    """
    Streams from source Drive file to the resumable upload URL using fixed-size chunks.
    Returns the final response JSON of the created file (id, name, ...)
    """
    # Prepare source stream (download)
    # Note: alt=media delivers raw bytes; stream=True yields the iterator.
    src_url = f"https://www.googleapis.com/drive/v3/files/{source_file_id}?alt=media&supportsAllDrives=true"
    src_resp = authed_session.get(src_url, stream=True)
    if src_resp.status_code != 200:
        raise RuntimeError(f"Failed to read source media: {src_resp.status_code} {src_resp.text}")

    # If size unknown, try to read from headers
    if total_size is None:
        total_size = int(src_resp.headers.get("Content-Length") or 0) or None

    start = 0
    buf = bytearray()
    for chunk in src_resp.iter_content(chunk_size=64 * 1024):  # read small pieces to assemble our fixed CHUNK_SIZE
        if chunk:
            buf.extend(chunk)
            if len(buf) >= chunk_size:
                # flush a full chunk
                end = start + chunk_size - 1
                _resumable_put_with_retry(
                    authed_session, upload_url, bytes(buf[:chunk_size]), start, end, total_size, retry_max
                )
                start = end + 1
                del buf[:chunk_size]
                _print_progress(start, total_size)

    # flush remainder
    if len(buf) > 0:
        end = start + len(buf) - 1
        _resumable_put_with_retry(authed_session, upload_url, bytes(buf), start, end, total_size, retry_max)
        start = end + 1
        _print_progress(start, total_size)

    # finalize: the last PUT that completes should return 200/201 with file JSON
    # If we never received final JSON (rare with some proxies), query the session status:
    # Send empty body with Content-Range: bytes */total to learn committed range;
    # however, Google usually responds with JSON on final part, so we assume last call returned JSON.
    # To be safe, perform a final status query:
    finalize_headers = {"Content-Range": f"bytes */{total_size}" if total_size is not None else "bytes */*"}
    finalize = authed_session.put(upload_url, headers=finalize_headers)
    # 308 means "resume incomplete" which is odd after finishing; ignore if we already finished.
    if finalize.status_code in (200, 201):
        try:
            return finalize.json()
        except Exception:
            pass
    # If finalize didn't return JSON, the previous successful PUT likely did.
    # There's no portable way to fetch the created file id from the session URL,
    # so we instruct caller to re-check via listing or just continue the flow if we have it.

    # As a fallback, error out with a helpful message—caller can retry.
    raise RuntimeError("Upload completed but finalization did not return file metadata JSON. "
                       "Try smaller CHUNK_SIZE or re-run.")


def _resumable_put_with_retry(
    authed_session: AuthorizedSession,
    upload_url: str,
    data: bytes,
    start: int,
    end: int,
    total_size: Optional[int],
    retry_max: int
) -> Response:
    headers = {
        "Content-Length": str(len(data)),
        "Content-Type": "application/octet-stream",
        "Content-Range": _content_range(start, end, total_size),
    }
    attempt = 0
    backoff = 1.0
    while True:
        resp = authed_session.put(upload_url, headers=headers, data=data)
        # 308 is "Resume Incomplete" (expected for non-final chunks)
        if resp.status_code in (200, 201, 308):
            return resp
        attempt += 1
        if attempt > retry_max:
            raise RuntimeError(f"Resumable PUT failed permanently: {resp.status_code} {resp.text}")
        time.sleep(backoff)
        backoff = min(backoff * 2.0, 30.0)
        # Probe session to learn committed range and adjust (robust resume)
        probe = authed_session.put(upload_url, headers={"Content-Range": f"bytes */{total_size or '*'}"})
        if probe.status_code == 308:
            range_hdr = probe.headers.get("Range")
            # Range like: "bytes=0-1048575"
            if range_hdr and range_hdr.startswith("bytes=") and "-" in range_hdr:
                committed_end = int(range_hdr.split("-")[1])
                next_start = committed_end + 1
                if next_start != start:
                    # adjust our window and resend only the missing part
                    offset = next_start - start
                    data = data[offset:]
                    start = next_start
                    headers["Content-Length"] = str(len(data))
                    headers["Content-Range"] = _content_range(start, start + len(data) - 1, total_size)
        # loop to retry


def _content_range(start: int, end: int, total: Optional[int]) -> str:
    if total is None:
        return f"bytes {start}-{end}/*"
    return f"bytes {start}-{end}/{total}"


def _print_progress(done: int, total: Optional[int]):
    if total:
        pct = (done / total) * 100.0
        print(f"\rUploading... {pct:6.2f}% ({done}/{total} bytes)", end="", flush=True)
    else:
        mb = done / (1024 * 1024)
        print(f"\rUploading... {mb:,.2f} MB", end="", flush=True)


def move_file(drive, file_id: str, add_parent: str, remove_parent: Optional[str]):
    try:
        result = drive.files().update(
            fileId=file_id,
            addParents=add_parent,
            removeParents=remove_parent or "",
            fields="id, parents",
            supportsAllDrives=True
        ).execute()
        logging.info(f"Move operation successful for file {file_id}")
        return result
    except Exception as e:
        logging.error(f"Failed to move file {file_id}: {str(e)}")
        raise


def delete_file(drive, file_id: str):
    drive.files().delete(fileId=file_id, supportsAllDrives=True).execute()

def is_file_old_enough(file_info: dict) -> bool:
    """
    Check if the file is less than 2 days old.
    """
    if 'modifiedTime' not in file_info:
        return False
    
    modified_time = datetime.fromisoformat(file_info['modifiedTime'].replace('Z', '+00:00'))
    two_days_ago = datetime.now(modified_time.tzinfo) - timedelta(days=30)
    
    return modified_time > two_days_ago


def load_state() -> Dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_state(state: Dict):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def scan_folder(drive, authed_session, folder_id: str, folder_name: str, auto_fix: bool = False, keep_versions: bool = False) -> list:
    """
    Scans a folder for problematic videos.
    Returns list of problematic video IDs, or fixes them if auto_fix=True.
    Files are kept in their original folder during the process.
    """
    # Setup folder-specific logging
    log_file = setup_logging(folder_name)
    logging.info(f"=== Starting scan of folder: {folder_name} ===")
    logging.info(f"Folder ID: {folder_id}")
    logging.info(f"Log file: {log_file}")
    
    # Clean up any leftover temp files from previous runs
    logging.info("Checking for leftover temporary files...")
    cleanup_temp_files(drive, folder_id)
    results = []
    
    try:
        # List all files in the folder
        query = f"'{folder_id}' in parents and (mimeType contains 'video/')"
        files = drive.files().list(
            q=query,
            fields="files(id,name,mimeType,size,thumbnailLink,videoMediaMetadata,createdTime,modifiedTime)",
            supportsAllDrives=True,
            includeItemsFromAllDrives=True
        ).execute()

        total_videos = len(files.get('files', []))
        logging.info(f"Found {total_videos} videos to check in {folder_name}")

        for idx, file in enumerate(files.get('files', []), 1):
            # Skip files less than 2 days old
            if not is_file_old_enough(file):
                logging.info(f"\nSkipping {file['name']} - less than 2 days old")
                continue
                
            logging.info(f"\nProcessing File {idx}/{total_videos}")
            log_video_details(file)
            
            ready, reason = is_preview_ready(authed_session, file)
            if ready:
                logging.info(f"Status: [OK] Playback OK ({reason})")
            else:
                logging.warning(f"Status: [!!] Problem detected ({reason})")
                if auto_fix:
                    logging.info(f"Starting auto-fix for {file['name']}")
                    try:
                        # Use same folder as source for temp, final, and archive
                        reupload_video(
                            authed_session=authed_session,
                            drive=drive,
                            file_id=file['id'],
                            temp_folder_id=folder_id,    # Keep in same folder
                            final_folder_id=folder_id,   # Keep in same folder
                            archive_folder_id=folder_id, # Archive in same folder
                            archive_original=True,
                            mime_override="video/mp4",
                            retry_count=10
                        )
                        logging.info("✅ Fix completed successfully")
                    except Exception as e:
                        logging.error(f"❌ Failed to fix {file['name']}: {e}")
                results.append({
                    'id': file['id'],
                    'name': file['name'],
                    'folder': folder_name,
                    'reason': reason,
                    'size': file.get('size', 'unknown'),
                    'created': file.get('createdTime', 'unknown'),
                    'modified': file.get('modifiedTime', 'unknown')
                })
    except Exception as e:
        print(f"Error scanning folder {folder_id}: {e}")
    
    return results

def cleanup_temp_files(drive, folder_id: str, original_name: str = None):
    """Clean up temporary files from previous runs or specific file reuploads"""
    try:
        # Build query based on whether we're cleaning up a specific file or all temp files
        if original_name:
            base_name = os.path.splitext(original_name)[0]
            query = f"'{folder_id}' in parents and name contains '{base_name}-reupload'"
        else:
            query = f"'{folder_id}' in parents and name contains '-reupload'"
            
        files = drive.files().list(
            q=query,
            fields="files(id,name,createdTime)",
            supportsAllDrives=True,
            includeItemsFromAllDrives=True
        ).execute()
        
        for file in files.get('files', []):
            try:
                logging.info(f"Cleaning up temp file: {file['name']} (created: {file.get('createdTime', 'unknown')})")
                delete_file(drive, file['id'])
                logging.info(f"Successfully deleted: {file['name']}")
            except Exception as e:
                logging.warning(f"Failed to delete temp file {file['name']}: {e}")
    except Exception as e:
        logging.warning(f"Failed to search for temp files: {e}")

def cleanup_old_versions(drive, folder_id: str, file_name: str, keep_latest: bool = True):
    """Clean up old versions of a reuploaded file"""
    try:
        base_name = os.path.splitext(file_name)[0]
        query = f"'{folder_id}' in parents and name contains '{base_name}' and name != '{file_name}'"
        
        files = drive.files().list(
            q=query,
            fields="files(id,name,createdTime)",
            orderBy="createdTime desc",
            supportsAllDrives=True,
            includeItemsFromAllDrives=True
        ).execute()
        
        file_list = files.get('files', [])
        if keep_latest and len(file_list) > 0:
            file_list = file_list[1:]  # Skip the most recent version
            
        for file in file_list:
            try:
                logging.info(f"Cleaning up old version: {file['name']} (created: {file.get('createdTime', 'unknown')})")
                delete_file(drive, file['id'])
                logging.info(f"Successfully deleted old version: {file['name']}")
            except Exception as e:
                logging.warning(f"Failed to delete old version {file['name']}: {e}")
    except Exception as e:
        logging.warning(f"Failed to search for old versions: {e}")

def reupload_video(
    authed_session: AuthorizedSession,
    drive,
    file_id: str,
    temp_folder_id: str,
    final_folder_id: str,
    archive_folder_id: str,
    archive_original: bool = True,
    mime_override: str = "video/mp4",
    retry_count: int = 10
) -> bool:
    """Helper function to reupload a single video with the standard parameters"""
    meta = get_file_metadata(drive, file_id)
    size = int(meta.get("size") or 0) or None
    
    # Decide target MIME and name
    target_mime = mime_override or meta.get("mimeType", "video/mp4")
    base_name = meta.get("name", f"{file_id}.mp4")
    new_name = _append_suffix_before_ext(base_name, "-reupload")

    # Start update upload
    print(f"Starting update of '{base_name}'...")
    upload_url = create_resumable_session(
        authed_session=authed_session,
        name=new_name,
        mime_type=target_mime,
        file_id=file_id  # Update existing file
    )

    new_file_json = stream_copy_drive_to_resumable(
        authed_session=authed_session,
        source_file_id=file_id,
        upload_url=upload_url,
        total_size=size,
        chunk_size=CHUNK_SIZE,
        retry_max=5
    )
    
    new_file_id = new_file_json.get("id")
    if not new_file_id:
        raise RuntimeError("Upload completed but no new file ID returned")

    # Poll preview and move files
    total_wait_time = retry_count * 60  # Total wait time in seconds
    logging.info(f"Starting preview check - will try for up to {total_wait_time/60:.1f} minutes")
    logging.info(f"File ID being checked: {new_file_id}")
    
    for i in range(retry_count):
        try:
            new_meta = get_file_metadata(drive, new_file_id)
            ok, why = is_preview_ready(authed_session, new_meta)
            if ok:
                logging.info(f"Preview became available after {(i+1)*60} seconds")
                logging.info(f"Moving file {new_file_id} to final folder {final_folder_id}")
                
                # Verify file exists before moving
                try:
                    verify_meta = get_file_metadata(drive, new_file_id)
                    if not verify_meta:
                        raise RuntimeError(f"File {new_file_id} not found before move operation")
                    
                    # Move new file to final folder
                    move_file(drive, new_file_id, add_parent=final_folder_id, remove_parent=temp_folder_id)
                    logging.info(f"Successfully moved file to final folder")
                except Exception as move_error:
                    logging.error(f"Failed to move file: {move_error}")
                    raise
                
                # Clean up any temporary files for this video
                cleanup_temp_files(drive, temp_folder_id, original_name=base_name)
                
                # Archive or delete original and clean up old versions
                if archive_original:
                    move_file(drive, file_id, add_parent=archive_folder_id, 
                            remove_parent=meta.get("parents", [None])[0])
                    cleanup_old_versions(drive, archive_folder_id, meta["name"], keep_latest=True)
                else:
                    delete_file(drive, file_id)
                    cleanup_old_versions(drive, final_folder_id, new_meta["name"], keep_latest=True)
                
                return True
        except Exception as e:
            print(f"Preview poll error: {e}")
        time.sleep(30)  # 30 second delay between retries
    
    return False

def log_video_details(file_info: dict, log: logging.Logger = logging) -> None:
    """Log detailed information about a video file."""
    log.info("=== Video Details ===")
    log.info(f"Name: {file_info.get('name', 'unknown')}")
    log.info(f"ID: {file_info.get('id', 'unknown')}")
    log.info(f"MIME Type: {file_info.get('mimeType', 'unknown')}")
    log.info(f"Size: {file_info.get('size', 'unknown')} bytes")
    log.info(f"Created: {file_info.get('createdTime', 'unknown')}")
    log.info(f"Modified: {file_info.get('modifiedTime', 'unknown')}")
    
    # Video specific metadata
    video_meta = file_info.get('videoMediaMetadata', {})
    if video_meta:
        log.info("Video Metadata:")
        log.info(f"  Duration: {video_meta.get('durationMillis', 'unknown')} ms")
        log.info(f"  Width: {video_meta.get('width', 'unknown')}")
        log.info(f"  Height: {video_meta.get('height', 'unknown')}")
        log.info(f"  Status: {video_meta.get('processingStatus', 'unknown')}")
    
    # Thumbnail information
    log.info(f"Has Thumbnail: {'thumbnailLink' in file_info}")
    
    # Parent folder information
    parents = file_info.get('parents', [])
    if parents:
        log.info(f"Parent Folder(s): {', '.join(parents)}")
    
    log.info("===================")

def setup_logging(folder_name=None):
    """Setup logging to both file and console. Creates separate log files per folder."""
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if folder_name:
        # Sanitize folder name for file system
        safe_folder_name = "".join(c for c in folder_name if c.isalnum() or c in " _-")
        log_file = os.path.join(log_dir, f"{safe_folder_name}_{timestamp}.log")
    else:
        log_file = os.path.join(log_dir, f"video_check_{timestamp}.log")
    
    # Remove existing handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    # Setup file handler
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(levelname)s | %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return log_file

def main():
    ap = argparse.ArgumentParser(description="Drive re-uploader (no local disk) to fix non-previewable videos.")
    ap.add_argument("--file", required=False, help="Drive file ID or /file/d/<id>/preview URL")
    ap.add_argument("--scan-folders", action="store_true", help="Scan folders defined in .env for problematic videos")
    ap.add_argument("--auto-fix", action="store_true", help="Automatically fix problematic videos found during scan")
    ap.add_argument("--temp-folder", required=False, help="Temp folder ID where new upload initially goes")
    ap.add_argument("--final-folder", required=False, help="Final folder ID where new upload should live")
    ap.add_argument("--archive-original", default="false", choices=["true", "false"], help="Archive original instead of deleting")
    ap.add_argument("--archive-folder", default=None, help="Archive folder ID (required if --archive-original=true)")
    ap.add_argument("--mime-override", default=None, help="Force MIME type on upload (e.g., video/mp4)")
    ap.add_argument("--retry-count", type=int, default=12, help="Preview poll retries (default: 12)")
    ap.add_argument("--retry-delay-seconds", type=int, default=60, help="Delay between preview polls in seconds (default: 60)")
    ap.add_argument("--keep-name", default="false", choices=["true", "false"], help="Keep exact original name (else append -reupload)")
    ap.add_argument("--dry-run", default="false", choices=["true", "false"], help="Only report status; do not modify")
    ap.add_argument("--keep-versions", default="false", choices=["true", "false"], help="Keep old versions when fixing videos")
    args = ap.parse_args()

    file_id = parse_file_id(args.file) if args.file else None
    archive_original = args.archive_original == "true"
    keep_name = args.keep_name == "true"
    dry_run = args.dry_run == "true"
    keep_versions = args.keep_versions == "true"

    # Setup logging
    log_file = setup_logging()
    logging.info("=== Drive Video Reuploader Starting ===")
    logging.info(f"Log file: {log_file}")
    
    if not args.scan_folders and not args.file:
        logging.error("Either --file or --scan-folders is required")
        sys.exit(2)
    
    # Validate arguments based on mode
    if args.file and not args.scan_folders:
        # Only enforce folder arguments for single file mode
        if not args.temp_folder or not args.final_folder:
            logging.error("--temp-folder and --final-folder are required for single file mode")
            sys.exit(2)
        if archive_original and not args.archive_folder:
            logging.error("--archive-folder is required when --archive-original=true in single file mode")
            sys.exit(2)

    authed_session, drive = setup_auth()
    logging.info("Authentication successful")
    
    if args.scan_folders:
        # Get folder IDs from environment
        folders = {k:v for k,v in os.environ.items() if k.startswith('DRIVE_FOLDER_')}
        if not folders:
            print("No DRIVE_FOLDER_* entries found in .env file")
            sys.exit(1)
            
        folder_count = len(folders)
        logging.info(f"Found {folder_count} folders to scan")
        all_problems = []
        
        for env_key, folder_id in folders.items():
            folder_name = env_key.replace('DRIVE_FOLDER_', '')
            logging.info(f"\nProcessing folder {folder_name}")
            logging.info(f"Using folder ID {folder_id} for operations (temp/final/archive)")
            problems = scan_folder(drive, authed_session, folder_id, folder_name, args.auto_fix, keep_versions)
            if problems:
                print(f"\n📁 Found {len(problems)} problematic videos in {folder_name}")
                all_problems.extend(problems)
            else:
                print(f"\n✅ No problems found in {folder_name}")
                
        if all_problems:
            print("\n📊 Summary of all problematic videos:")
            by_folder = {}
            for p in all_problems:
                if p['folder'] not in by_folder:
                    by_folder[p['folder']] = []
                by_folder[p['folder']].append(p)
            
            for folder, problems in by_folder.items():
                print(f"\n📁 {folder} ({len(problems)} issues):")
                for p in problems:
                    print(f"  - {p['name']} ({p['id']})")
                    print(f"    Reason: {p['reason']}")
        else:
            print("\n✅ No problematic videos found in any folder")
            
        sys.exit(0)

    # Idempotency check
    state = load_state()
    if file_id in state:
        mapped = state[file_id]
        print(f"Found prior reupload mapping: original={file_id} -> new={mapped.get('new_file_id')}")
        # Re-check preview on the mapped new file
        try:
            new_meta = get_file_metadata(drive, mapped["new_file_id"])
            ready, reason = is_preview_ready(authed_session, new_meta)
            if ready:
                print(f"PREVIEW READY fileId={new_meta['id']} via {reason}")
                sys.exit(0)
            else:
                print(f"Previously reuploaded file is still not previewable ({reason}); continuing flow.")
        except Exception as e:
            print(f"Warning: could not inspect mapped reupload: {e}; continuing flow.")

    # Inspect original
    meta = get_file_metadata(drive, file_id)
    size = int(meta.get("size") or 0) or None

    if not meta.get("mimeType", "").startswith("video/"):
        print(f"Skipping: file is not a video (mimeType={meta.get('mimeType')})")
        sys.exit(0)

    ready, reason = is_preview_ready(authed_session, meta)
    health = audit_upload_health(meta)
    print("UploadHealth:")
    print(f"  name: {health['name']}")
    print(f"  mimeType: {health['mimeType']}  {'❌' if health['badMime'] else '✅'}")
    print(f"  hasVideoMeta: {health['hasVideoMeta']}")
    print(f"  ext: {health['ext']}")

    if ready:
        print(f"OK: Already previewable ({reason}). PREVIEW READY fileId={file_id}")
        sys.exit(0)

    if dry_run:
        print(f"DRY-RUN: Not previewable now ({reason}). Would reupload via streaming.")
        sys.exit(0)

    # Decide target MIME
    target_mime = args.mime_override or ( "video/mp4" if health["badMime"] else meta.get("mimeType", "video/mp4") )
    # Decide new name
    base_name = meta.get("name", f"{file_id}.mp4")
    new_name = base_name if keep_name else _append_suffix_before_ext(base_name, "-reupload")

    print(f"Starting Drive→Drive streaming re-upload as '{new_name}' with MIME '{target_mime}'...")
    upload_url = create_resumable_session(authed_session, new_name, target_mime, args.temp_folder)

    new_file_json = stream_copy_drive_to_resumable(
        authed_session=authed_session,
        source_file_id=file_id,
        upload_url=upload_url,
        total_size=size,
        chunk_size=CHUNK_SIZE,
        retry_max=5
    )
    new_file_id = new_file_json.get("id")
    if not new_file_id:
        print("ERROR: Upload completed but no new file ID returned. Exiting.", file=sys.stderr)
        sys.exit(1)

    print("\nUpload finished. New file ID:", new_file_id)

    # Poll preview
    for i in range(args.retry_count):
        try:
            new_meta = get_file_metadata(drive, new_file_id)
            ok, why = is_preview_ready(authed_session, new_meta)
            if ok:
                print(f"New file is previewable ({why}).")
                break
            else:
                print(f"Preview not ready yet ({why}). Retry {i+1}/{args.retry_count} in {args.retry_delay_seconds}s ...")
        except Exception as e:
            print(f"Preview poll error: {e}. Retry {i+1}/{args.retry_count} in {args.retry_delay_seconds}s ...")
        time.sleep(args.retry_delay_seconds)
    else:
        print("FAILED: New file never became previewable within retry window. Leaving both files intact.")
        # record mapping anyway for future runs
        state[file_id] = {"new_file_id": new_file_id, "ts": int(time.time())}
        save_state(state)
        sys.exit(1)

    # Clean up any remaining temp files
    cleanup_temp_files(drive, args.temp_folder)
    
    # Move new file to final folder (remove temp)
    print("Moving new file to final folder ...")
    move_file(drive, new_file_id, add_parent=args.final_folder, remove_parent=args.temp_folder)

    # Archive or delete original
    if archive_original:
        print("Archiving original file ...")
        move_file(drive, file_id, add_parent=args.archive_folder, remove_parent=meta.get("parents", [None])[0])
    else:
        print("Deleting original file ...")
        delete_file(drive, file_id)

    # Save mapping
    state[file_id] = {"new_file_id": new_file_id, "ts": int(time.time())}
    save_state(state)

    print("SUCCESS")
    print(f"original_file_id={file_id}")
    print(f"original_name={meta.get('name')}")
    print(f"new_file_id={new_file_id}")
    print(f"new_name={new_name}")
    print(f"final_folder_id={args.final_folder}")
    print("status=success")


def _append_suffix_before_ext(name: str, suffix: str) -> str:
    root, ext = os.path.splitext(name)
    return f"{root}{suffix}{ext}"


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)
    except Exception as e:
        import traceback
        print(f"\nERROR: {e}", file=sys.stderr)
        print("\nFull traceback:", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
