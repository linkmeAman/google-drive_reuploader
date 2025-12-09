# Drive Video Re-uploader — Architecture & End-to-End Flow

This document explains the purpose of the project, the full start-to-end behavior, the core concepts and algorithms used, and the important implementation details to understand, extend, or operate the tool safely.

## Purpose
- Repair Google Drive video files that are not previewable in the Drive web UI by re-uploading their media data using a Drive→Drive streaming process that never writes the video to local disk. The tool preserves links/permissions when requested and is memory-efficient (default ~16 MB chunks).

## High-level overview (single-sentence)
The tool checks video files for Drive preview readiness, and when a file is determined to be unprocessed or broken for preview, it streams the original file bytes into a resumable Drive upload session (either overwriting the same file ID or creating a new file), then polls until Drive reports the reuploaded item as processed, finally cleaning up or archiving originals.

## Modes of operation
- Single-file mode: operate on a single Drive file specified by ID or preview URL.
- Folder-scan mode: read folder IDs from environment variables (`DRIVE_FOLDER_*`), scan for videos with preview issues, and optionally auto-fix them.

## Key files and components
- `drive_video_reuploader.py`: main CLI, core logic and control flow.
- `access_token.py`: authentication helper used by `setup_auth()` (provides `get_drive_service` and tokens).
- `logs/`: runtime logs per run/folder.
- `.drive_reupload_state.json`: persistent small mapping used to remember prior reuploads (id → new_id, timestamp, preserve flag).

## Start-to-end flow (detailed)
1. CLI & args: the user supplies either `--file <id>` (single-file) or `--scan-folders` (folder mode), plus options like `--preserve-id`, `--temp-folder`, `--final-folder`, `--archive-original`, `--mime-override`, `--auto-fix`, `--retry-count`, and `--retry-delay-seconds`.
2. Authentication: `setup_auth()` imports routines from `access_token.py` and builds an `AuthorizedSession` and an authorized Drive `service` client. The tool supports OAuth or service account flows as configured.
3. Inspect file(s):
   - For each target video the script calls `get_file_metadata()` to read fields that include `videoMediaMetadata` and `thumbnailLink`.
   - `audit_upload_health()` inspects MIME type, extension and presence of `videoMediaMetadata` to flag likely issues (e.g., `application/octet-stream`).
4. Preview readiness detection: `is_preview_ready(authed_session, meta)` combines two signals:
   - Drive metadata: `videoMediaMetadata.processingStatus` (e.g., `PROCESSING`, `PROCESSED`, `FAILED`) and presence of thumbnails/dimensions.
   - HTML probe: a GET of the Drive preview page via `AuthorizedSession` to detect processing banners or error banners in the preview HTML. HTML is used only to enrich the reason, not to override unequivocal metadata reports.
5. Decision: If preview is already ready, the file is skipped. Otherwise, the tool proceeds to re-upload.
6. Create resumable session: `create_resumable_session()` requests a resumable upload session from Drive:
   - When `--preserve-id=true`: the upload session targets `files/<fileId>?uploadType=resumable` to overwrite the same file ID.
   - When creating a new file: the session is created with `files?uploadType=resumable` and optional `parents` to place the new file in a temp folder.
7. Stream copy: `stream_copy_drive_to_resumable()` performs the core streaming pipeline:
   - Opens a request to download the source bytes: `GET /drive/v3/files/<source>?alt=media` with `stream=True`.
   - Buffers incoming data into a local byte buffer until it has at least `CHUNK_SIZE` bytes (default 16 MB), then uploads that fixed-size block to the upload session via `_resumable_put_with_retry()`.
   - The final remainder is uploaded and a finalization probe is performed to obtain resulting file metadata.
   - Memory use is bounded by `CHUNK_SIZE` plus small overhead; there is no local file write.
8. Resumable PUT with retry: `_resumable_put_with_retry()` uploads a Content-Range chunk and implements:
   - Retries with exponential backoff when non-OK statuses appear.
   - When Drive returns `308 Resume Incomplete`, the tool reads the `Range` header to learn what bytes were committed and adjusts the next chunk to avoid retransmit of already-committed bytes.
   - The function raises a helpful error if retries are exhausted.
9. Create a monitor job: `reupload_video()` constructs a `ReuploadJob` instance representing the newly-uploaded file and the archival/cleanup plan. That `ReuploadJob` contains: `file_id`, `original_file_id`, `preserve_id` flag, folder IDs for temp/final/archive, retry configuration, and status tracking fields.
10. Asynchronous monitoring: the `ReuploadJob` is optionally added to a `pending_jobs` list. `process_pending_jobs()` periodically calls `job.check_once()` when `job.next_check` is due. `check_once()` calls `is_preview_ready()` on the target file; if ready it calls `finalize()`.
11. Finalization & cleanup: `ReuploadJob.finalize()` performs the following depending on flags:
   - If `preserve_id` is true: nothing needs moving; the file was overwritten in-place.
   - If a new file was created: move the processed file from `temp_folder` into `final_folder` and remove the temporary parent if appropriate.
   - Archive or delete original: when `archive_original` and `archive_folder` are provided the original file is moved into the archive; otherwise, the original is deleted.
   - Optionally call `cleanup_old_versions()` to remove stale copies if `keep_versions` is false.
12. Persistent state: on failure or completion the tool updates `.drive_reupload_state.json` so subsequent runs can detect prior mappings and avoid redundant work.

## Core concepts and design decisions
- No-local-disk streaming: avoids storing video files locally by piping Drive download to a resumable Drive upload in fixed-size chunks. This minimizes disk IO and allows arbitrary-large files without local storage constraints.
- Resumable upload sessions: uses Drive's resumable upload API to upload in chunks and recover from transient network errors.
- Chunking & bounded memory: assemble CHUNK_SIZE (default 16 MB) buffers from small iterator chunks provided by `requests.iter_content()` to keep peak memory low.
- Metadata-first readiness check: rely primarily on `videoMediaMetadata.processingStatus` and thumbnail presence; use HTML probing only to clarify reasons (processing banners, friendly error messages).
- Retry/backoff & probe: when a PUT fails, the code probes Drive's session status (`Content-Range: bytes */<total>`) and reads the `Range` response header to resume from the last committed byte.
- Preserve ID vs new ID modes: overwriting the same Drive ID keeps links/permissions intact but cannot archive the original (because it is overwritten). Creating a new file allows archival of the original, staging, and final placement.

## Important functions and data structures
- `setup_auth()` — builds `AuthorizedSession` and Drive `service` using `access_token.py` helpers.
- `is_preview_ready(authed_session, meta)` — central preview detection logic combining metadata and HTML probe.
- `create_resumable_session()` — obtains upload session URL (Location header).
- `stream_copy_drive_to_resumable()` — core streaming loop that reads from Drive and issues chunked PUTs.
- `_resumable_put_with_retry()` — resilient chunk PUT with backoff and resume handling.
- `ReuploadJob` — dataclass tracking monitor state, retries, finalization behavior and cleanup logic.

## CLI options and environment variables (summary)
- `--file`: single file ID or /file/d/<id>/preview URL.
- `--scan-folders`: scan all `DRIVE_FOLDER_*` entries from the environment.
- `--auto-fix`: automatically reupload and monitor during a folder scan.
- `--preserve-id` (default true): overwrite existing file ID instead of creating a new file.
- `--temp-folder`, `--final-folder`, `--archive-folder`: required when creating new file IDs and for archival.
- `--mime-override`: e.g., `video/mp4` to force a sane MIME type for Drive transcoding.
- `CHUNK_SIZE` (constant in code): controls memory usage and upload granularity.
- Environment: `CLIENT_ID`, `CLIENT_SECRET`, `REFRESH_TOKEN` or service-account auth via `GOOGLE_APPLICATION_CREDENTIALS` as provided by `access_token.py`.

## Logging & observability
- Per-folder/per-run logs are written to `logs/` and use `setup_logging()` to keep both console and file handlers.
- The tool prints progress (percent or MB) during streaming; higher-level events (start/finish/retries/errors) are logged and surfaced to the user.

## Edge cases, failure modes & mitigations
- Finalization missing JSON: some proxies may not return final JSON on the last PUT; the code attempts a final probe and returns the last known JSON or raises a clear error suggesting smaller `CHUNK_SIZE` or re-run.
- Transient network failures: `_resumable_put_with_retry()` implements exponential backoff and uses the resumable session `Range` header to resume at the committed byte.
- Permissions errors (403/404): `is_preview_ready()` returns a reason including `html:perm_or_notfound` and the file will be reported as problematic.
- Recently uploaded files: the scanner skips files younger than a threshold to avoid interfering with in-flight uploads (code checks `modifiedTime` against a threshold).

## Security & privacy considerations
- The tool uses OAuth/service-account credentials to access Drive. Keep credentials and `.drive_reupload_state.json` private and secure.
- When running with `--preserve-id=true` you overwrite the existing file in-place — this preserves sharing settings but must be used with care.
- Archival mode moves originals to a specified archive folder rather than deleting them, which preserves recoverability.

## Extensibility points
- Replace `CHUNK_SIZE` to tune memory vs network efficiency.
- Add alternative probes (e.g., direct API fields, or a different HTML parsing heuristic) in `is_preview_ready()`.
- Integrate job queue systems for large-scale monitoring instead of the in-process `pending_jobs` list.
- Add metrics exporters (Prometheus) by instrumenting upload/monitor events.

## Troubleshooting checklist
1. Confirm environment variables / `.env` entries for `DRIVE_FOLDER_*` and credentials.
2. Check `logs/` for per-run details and traceback on failures.
3. If an upload finishes but finalization fails, try decreasing `CHUNK_SIZE` and re-run.
4. Use `--dry-run` to inspect detection logic without performing uploads.

## Summary
This project is designed to reliably and efficiently repair Drive videos that fail to be previewable by Drive's web UI. Its core is a robust Drive→Drive streaming pipeline using resumable upload sessions and chunked transfers with resume and retry support, plus a conservative preview-detection mechanism that combines Drive metadata and an HTML probe. It balances safety (preserve-id option / archival) with automation (folder scanning and `--auto-fix`).

---
If you want, I can:
- Add this summary to the repository `README.md` or link to this file from the top-level README.
- Produce a short quickstart or a diagram of the flow.
