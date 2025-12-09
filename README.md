# Google Drive Video Re-upload Tool

A Python tool that fixes non-previewable videos in Google Drive by re-uploading them through a Drive-to-Drive streaming process. It automatically detects videos that aren't properly processed by Google Drive's preview system and fixes them without downloading to local disk.

## Key Features

- **Folder Scanning**: Automatically scans specified folders for problematic videos
- **Zero Disk Usage**: Streams files directly between Google Drive
- **Memory Efficient**: Uses only ~16MB RAM regardless of video size
- **Smart Processing**: Detects and fixes videos with preview issues
- **Parallel Preview Monitoring**: Uploads continue in the background while the script scans the next videos
- **Metadata-First Preview Checks**: Uses Drive processingStatus/thumbnail/dimensions to avoid false "ready" signals that require manual browser visits
- **Preview Priming**: After each upload, the Drive preview page is hit once so transcoding starts without you opening the link
- **Optional Parallel Uploads**: Re-upload multiple files at once with `--max-upload-workers` to speed up folder auto-fix runs
- **Detailed Logging**: Tracks all operations with timestamps
- **Flexible File Handling**: Preserve the original Drive ID by default or opt-in to generate a fresh copy

## Setup

1. **Required Packages**:
   ```
   google-api-python-client
   google-auth
   google-auth-oauthlib
   requests
   python-dotenv
   ```

2. **Python Environment** (3.9+):
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Configuration**:
   Create `.env` file with your credentials and folder IDs:
   ```env
   # Authentication
   CLIENT_ID=your_client_id
   CLIENT_SECRET=your_client_secret
   REFRESH_TOKEN=your_refresh_token

   # Folder IDs
   DRIVE_FOLDER_CAMERA_RECORDING=folder_id_1
   DRIVE_FOLDER_TT_FORMS=folder_id_2
   DRIVE_FOLDER_ZOOM_RECORDINGS=folder_id_3
   ```

## Usage

### 1. Scan Mode (Recommended)
Checks all configured folders for problematic videos:
```powershell
# Just scan and report issues
python drive_video_reuploader.py --scan-folders

# Scan and automatically fix issues
python drive_video_reuploader.py --scan-folders --auto-fix 
With preview python drive_video_reuploader.py --scan-folders --auto-fix --open-preview

# Faster auto-fix with concurrent uploads
python drive_video_reuploader.py --scan-folders --auto-fix --max-upload-workers 3 --preview-timeout-minutes 90
```

### 2. Single File Mode
Fix a specific video while keeping its Drive ID (default behaviour):
```powershell
python drive_video_reuploader.py --file "1HfkJOA72po-ykYoVq617WQk0wxiNl6zD"
```

Create a brand-new file ID instead (requires staging folders):
```powershell
python drive_video_reuploader.py --file "1HfkJOA72po-ykYoVq617WQk0wxiNl6zD" ^
  --preserve-id false ^
  --temp-folder "14JYr4ugdFnp-wAGnC32mkTh1DyLeYMUv" ^
  --final-folder "14JYr4ugdFnp-wAGnC32mkTh1DyLeYMUv" ^
  --archive-original true ^
  --archive-folder "1A2B3CArchiveFolder"
```

## How It Works

### Process Flow
1. **Scanning**: Checks each video in configured folders
2. **Detection**: Identifies videos with preview problems
3. **Update**: Streams and updates problematic videos through the Drive API
4. **Asynchronous Monitoring**: Preview readiness is polled in the background so the scan can keep moving
5. **Verification & Cleanup**: Once Drive reports a PROCESSED status, the script finalises moves/archival and removes temporary artifacts

### Preview Timeout Control
- Use `--preview-timeout-minutes` (default 60) to keep polling until Drive finishes transcoding, even for long videos. The tool automatically scales the retry count to cover the requested timeout with the chosen poll interval.
- Use `--wait-first-minutes` (default 15) to hold off on reuploading while the original file might still finish processing. Set to `0` to disable the wait. If preview comes up during this window, reupload is skipped.
- Use `--max-upload-workers` to reupload multiple files concurrently during folder auto-fix; preview polling runs in the background for all active uploads.
- Preview readiness checks now trust Drive metadata (processingStatus + thumbnail/dimensions) and only use the HTML viewer to confirm failures, preventing false "ready" reports that require manual browser visits.

### Logging
- Detailed logs stored in `logs` directory
- Each run creates a timestamped log file
- Tracks all operations and their results

### File Management
- **Temporary Files**: Only needed when creating a brand-new file ID; the cleanup logic skips active uploads and removes leftovers afterwards
- **File IDs**: Preserved by default; switch `--preserve-id=false` to stage a brand-new copy
- **Processing**: Files are updated in-place, so sharing links, permissions, and automations stay intact unless you opt into the new-ID mode

### Advanced Options
- `--retry-count` / `--retry-delay-seconds` (default 120s): Tune how long preview polling should continue (useful for multi-GB uploads)
- `--auto-fix`: When scanning folders, automatically trigger reuploads and let the background monitor finish them
- `--keep-versions`: Retain old revisions when creating new IDs instead of trimming stale copies
- `--open-preview`: After each re-upload, open the Google Drive preview page in your default browser so you can watch the processing banner clear in real time

## Tips
- Use `--scan-folders` for automated checking of all folders
- Add `--auto-fix` to automatically repair problematic videos
- Check logs in `logs` directory for detailed operation history
- Videos stay in their original folders throughout the process

## License

MIT
