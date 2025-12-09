# Drive Video Reuploader – Detailed Walkthrough

This project repairs Google Drive videos that refuse to show the preview player. It does so by streaming the bytes from the existing Drive object into a fresh upload session (optionally overwriting the same file ID), then polling until Drive reports that the new upload is processed. Nothing is ever written to local disk, and memory stays bounded by a fixed chunk size (default 16 MB).

## Core Purpose
- Detect videos in Google Drive that are stuck processing or have bad MIME/codec metadata.
- Re-upload them directly within Drive so the transcoder runs again and the preview player starts working.
- Keep sharing links intact by default (overwrites the same file ID), while offering an opt-in path to create a brand-new copy with archival/cleanup rules.

## Authentication & Configuration
- Credentials are loaded from `.env` via `access_token.py`. Required keys: `CLIENT_ID`, `CLIENT_SECRET`, `REFRESH_TOKEN`, optional `ACCESS_TOKEN` cache.
- `access_token.py` refreshes tokens when needed, persists refreshed `ACCESS_TOKEN` back to `.env`, and builds the Drive client plus an `AuthorizedSession` for raw HTTP calls.
- Folder scan mode reads `DRIVE_FOLDER_*` entries from `.env` to know which Drive folders to inspect.
- State persistence: `.drive_reupload_state.json` remembers prior reupload mappings to avoid duplicate work.

## High-Level Flow (Start to Finish)
1. **Parse CLI flags** in `drive_video_reuploader.py` (single-file mode or folder scan, plus behaviors like `--auto-fix`, `--preserve-id`, retry timings, naming rules, archiving).
2. **Set up logging** (timestamped file under `logs/` plus console output).
3. **Authenticate** using `setup_auth()` → Drive SDK client + `AuthorizedSession` with refreshed tokens.
4. **Mode dispatch**:
   - **Folder Scan (`--scan-folders`)**: iterate all `DRIVE_FOLDER_*` env vars; for each folder call `scan_folder()`.
   - **Single File**: work against the provided file ID or preview URL.
5. **Health check**:
   - Fetch metadata via Drive API.
   - Judge preview readiness with `is_preview_ready()` (metadata-first: processingStatus + thumbnail/dimensions). The HTML preview page is probed only to detect processing/error banners, never to mark a file as ready on its own.
   - If already previewable (or non-video), exit early; otherwise continue.
6. **Decide upload plan**:
   - Choose target MIME (explicit override, else `video/mp4` if MIME looks bad, else existing MIME).
   - Decide whether to overwrite the same ID (`--preserve-id=true`) or create a new file in a temp/final folder pair with optional archival. Folder auto-fix can run multiple uploads concurrently via `--max-upload-workers`.
7. **Re-upload by streaming**:
   - Open a resumable upload session (`create_resumable_session`) for either an in-place update (PATCH) or a new file (POST to temp folder).
   - Stream bytes from the source file (`stream_copy_drive_to_resumable`) using the `AuthorizedSession`, sending fixed-size chunks with Content-Range and resumable retry/backoff logic.
   - On success, capture the target file ID (same as original if preserving).
8. **Monitor preview processing**:
   - Touch the Drive preview page once to trigger transcoding without requiring the user to open it manually.
   - Wrap the upload in a `ReuploadJob` that polls metadata/preview banners on a schedule (`check_once`, `block_until_ready`), honoring retry counts and delays.
   - In folder auto-fix mode, uploads run in a worker pool (`max_upload_workers`) while a lightweight background loop keeps polling preview readiness for all active jobs.
9. **Finalize & cleanup** once Drive reports the file as processed:
   - If using a new ID: move from temp to final folder, archive or delete the original per flags, optionally prune older versions.
   - If preserving ID: nothing moves—link, permissions, and automations stay intact.
   - Remove leftover temp artifacts and persist success mapping in `.drive_reupload_state.json`.
10. **Report results** to stdout and logs, including success/failure reason and destination folder.

## Folder Scan Logic
- `scan_folder()` lists all video MIME items in the folder.
- Skips very recent uploads (modified within the configurable wait window, default ~15 minutes) to avoid racing Drive’s normal processing.
- For each file:
  - Log details via `log_video_details`.
  - Evaluate preview readiness; if bad and `--auto-fix`, submit the wait + reupload work to the upload pool (`max_upload_workers`) and let the background monitor poll preview readiness for all active jobs; otherwise record the issue for the final summary.
- After scanning, it waits for all queued uploads/monitors to finish or exhaust retries, then prints a per-folder and global summary.

## Single File Logic
- Validate arguments (temp/final/archive folders required when not preserving ID).
- If a previous mapping exists in `.drive_reupload_state.json`, re-check its preview status before doing work.
- Perform the same readiness check, then stream-reupload, then block until processed.
- Writes mapping to state file so a rerun can skip redundant uploads.

## Important Behaviors & Safeguards
- **No local disk usage**: streaming uses HTTP range requests and resumable upload chunks; RAM bounded by `CHUNK_SIZE` (16 MB).
- **Resilience**: resumable upload supports retries, probes server-acknowledged ranges, and resumes from partial commits.
- **Preview priming**: after each upload, the tool hits the Drive preview URL once so processing begins without requiring a manual browser visit.
- **Cleanup**: removes temp reupload artifacts and older versions (unless `--keep-versions`), while archiving originals when requested.
- **Safety defaults**: preserves the original file ID unless explicitly told to create a new copy; refuses to archive when preserving ID to avoid destroying the only copy.

## Where to Look in Code
- `drive_video_reuploader.py`: CLI entrypoint, scanning, upload orchestration, polling, and cleanup logic.
- `access_token.py`: token validation/refresh, Drive client construction, `.env` synchronization.
- `requirements.txt`: Python dependencies (Drive SDK, auth libs, requests, dotenv).

Use this document as the start-to-finish mental model when operating or extending the tool.
