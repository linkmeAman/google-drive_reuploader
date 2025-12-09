# Google Drive Video Re-upload Tool

Repairs non-previewable Google Drive videos by streaming the existing file into a fresh resumable upload (no local disk writes), then polling until Drive’s preview is ready.

## Features
- Folder scan + optional auto-fix for all `DRIVE_FOLDER_*` entries in `.env`
- Drive→Drive streaming, zero local disk, ~16MB bounded RAM
- Metadata-first + viewer-aware readiness detection to avoid false “ready” states
- Preview priming after upload so Drive transcoding starts without manual clicks
- Optional parallel uploads with background preview polling
- Preserves original Drive ID by default; can create a new ID with archive/cleanup rules
- Detailed timestamped logging under `logs/`

## Prerequisites
- Python 3.9+
- Dependencies: `google-api-python-client`, `google-auth`, `google-auth-oauthlib`, `requests`, `python-dotenv`

Install:
```bash
python3 -m venv venv
source venv/bin/activate    # Windows: .\venv\Scripts\activate
pip install -r requirements.txt
```

## Configure
Create a `.env` file:
```env
# Auth (OAuth installed app)
CLIENT_ID=your_client_id
CLIENT_SECRET=your_client_secret
REFRESH_TOKEN=your_refresh_token

# Folders to scan
DRIVE_FOLDER_CAMERA_RECORDING=folder_id_1
DRIVE_FOLDER_TT_FORMS=folder_id_2
DRIVE_FOLDER_ZOOM_RECORDINGS=folder_id_3
```
Service accounts are also supported via `GOOGLE_APPLICATION_CREDENTIALS`.

## Run
Scan folders (report only):
```bash
python3 drive_video_reuploader.py --scan-folders
```

Scan + auto-fix:
```bash
python3 drive_video_reuploader.py --scan-folders --auto-fix
```

Single file (preserve same ID):
```bash
python3 drive_video_reuploader.py --file "drive_file_id_or_preview_url"
```

Single file with new ID (requires staging folders):
```bash
python3 drive_video_reuploader.py --file "drive_file_id_or_preview_url" \
  --preserve-id false \
  --temp-folder "TEMP_FOLDER_ID" \
  --final-folder "FINAL_FOLDER_ID" \
  --archive-original true \
  --archive-folder "ARCHIVE_FOLDER_ID"
```

## Key defaults & options
- Preview polling: `--retry-delay-seconds` default 180s; `--retry-count` default 12
- Memory: `CHUNK_SIZE` 16 MB; streaming only, no local video writes
- Naming: keeps original name when overwriting; appends `-reupload` when creating a new file ID
- Concurrency: `--max-upload-workers` for faster auto-fix; background preview polling continues
- Safety: `--preserve-id=true` keeps sharing links/permissions; set `--preserve-id=false` to create a fresh copy and optionally archive the original

## How it works
1) Check metadata + preview HTML for readiness/banners  
2) If not ready, stream bytes from the original to a resumable upload session  
3) Prime the preview page to trigger Drive processing  
4) Poll readiness; when processed, move/archive/cleanup according to flags  

## Logs
- Per-run files in `logs/` (console + file handler).

## License
MIT
