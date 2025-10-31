# Google Drive Video Re-upload Tool

A Python tool that fixes non-previewable videos in Google Drive by re-uploading them through a Drive-to-Drive streaming process. It automatically detects videos that aren't properly processed by Google Drive's preview system and fixes them without downloading to local disk.

## Key Features

- **Folder Scanning**: Automatically scans specified folders for problematic videos
- **Zero Disk Usage**: Streams files directly between Google Drive
- **Memory Efficient**: Uses only ~16MB RAM regardless of video size
- **Smart Processing**: Detects and fixes videos with preview issues
- **Detailed Logging**: Tracks all operations with timestamps
- **File Safety**: Updates files in-place while preserving IDs and permissions

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
```

### 2. Single File Mode
Fix a specific video:
```powershell
python drive_video_reuploader.py --file "1HfkJOA72po-ykYoVq617WQk0wxiNl6zD" --temp-folder "14JYr4ugdFnp-wAGnC32mkTh1DyLeYMUv" --final-folder "14JYr4ugdFnp-wAGnC32mkTh1DyLeYMUv"
```

## How It Works

### Process Flow
1. **Scanning**: Checks each video in configured folders
2. **Detection**: Identifies videos with preview problems
3. **Update**: Streams and updates problematic videos in-place through Drive API
4. **Verification**: Ensures updated video is properly processed
5. **Cleanup**: Removes any temporary files

### Logging
- Detailed logs stored in `logs` directory
- Each run creates a timestamped log file
- Tracks all operations and their results

### File Management
- **Temporary Files**: Created during update process, automatically cleaned up
- **File IDs**: Preserved during update process
- **Processing**: Files are updated in-place, maintaining original location and ID

## Tips
- Use `--scan-folders` for automated checking of all folders
- Add `--auto-fix` to automatically repair problematic videos
- Check logs in `logs` directory for detailed operation history
- Videos stay in their original folders throughout the process

## License

MIT