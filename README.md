# Cloud Backup Automation Script

## Overview

This Python script automates the process of uploading backup files to Google Cloud Storage and Rackspace Cloud Files. It includes mechanisms for file locking, retrying failed operations, MD5 checksum verification for data integrity, and detailed logging.

## Requirements

- **Python 3.x**  
- Required libraries: `google-cloud-storage`, `pyrax`, `retrying`, `requests`

Install dependencies with:

```bash
pip install google-cloud-storage pyrax retrying requests
```
## Directory Structure

Before running the script, ensure the following directory structure exists in the working directory:

- **`cloud_backup.py`**: The main Python script file.
- **`conf`**: Directory containing the `ossbackup.conf` configuration file.
- **`failure`**: Directory where failed transfers will be moved.
- **`local_backups`**: Directory containing the backup files to be uploaded.
- **`logs`**: Directory where log files will be stored.

Ensure these directories are created and properly set up before executing the script.

## Configuration
1. Configuration File (cloud_backup.conf): This script reads from a configuration file that defines the environment (prod in this case). The configuration should include:

- storage_providers: Comma-separated list of storage providers (google, rackspace).
- google_bucket: Google Cloud Storage bucket name.
- rackspace_region: Rackspace region.
- rackspace_identity_type: Rackspace identity type.
- rackspace_user: Rackspace username.
- rackspace_api_key: Rackspace API key.
- worker_count: Number of parallel workers to handle uploads.
- backup_location: Path to the directory containing backups.
- failure_location: Path to the directory where failed transfers are moved.
- lock_path: Path to the lock file.
- log_location: Path to the log file.

2. Google Cloud Authentication:
Ensure you have authenticated your machine or environment with Google Cloud to use the Storage API by setting the GOOGLE_APPLICATION_CREDENTIALS environment variable to the path of your service account key file.

3. Rackspace Authentication:
Set the appropriate Rackspace credentials (region, user, API key) in the configuration file.

## Usage
Run the script by executing:
```bash
python3 cloud_backup.py
```

## Example
This example assumes that you have an hourly backup stored in the local_backups/ directory:
```bash
$ python3 cloud_backup.py
2024-09-04 12:26:05,728 - root - DEBUG - ---------START-----------
2024-09-04 12:26:05,728 - root - DEBUG - LockFile init: lockpath=/tmp/ossbackup.lock _lockfile=None
2024-09-04 12:26:05,728 - root - DEBUG - LockFile.lock() does not have self._lockfile.
2024-09-04 12:26:05,729 - root - DEBUG - LockFile.lock() attempting open() for append+ type(self._lockfile=<class 'NoneType'>)
2024-09-04 12:26:05,729 - root - DEBUG - LockFile.lock() seek to 0 / beginning of file
2024-09-04 12:26:05,729 - root - DEBUG - LockFile.lock() fpath.readline().rstrip()
2024-09-04 12:26:05,729 - root - DEBUG -
2024-09-04 12:26:05,729 - root - DEBUG - LockFile.lock() fpath.read()
2024-09-04 12:26:05,729 - root - DEBUG -
2024-09-04 12:26:05,729 - root - DEBUG - (end of read)
2024-09-04 12:26:05,729 - root - DEBUG - fpath.fileno()=4 [int file descriptor]
2024-09-04 12:26:05,729 - root - DEBUG - Wrote PID to lockfile, and now self._lockfile=<_io.TextIOWrapper name='/tmp/ossbackup.lock' mode='a+' encoding='UTF-8'> type=<class '_io.TextIOWrapper'>
2024-09-04 12:26:05,729 - root - INFO - storage provider(s): ['google']
2024-09-04 12:26:05,729 - root - INFO - Calculating Backups to Process...
local_backups/
2024-09-04 12:26:05,730 - root - DEBUG - (1) BACKUP_PATHS: ['local_backups//etc_backups-hourly.tar.gz']
2024-09-04 12:26:05,730 - root - ERROR - Unable to parse md5sum from filename: local_backups//etc_backups-hourly.tar.gz
2024-09-04 12:26:05,730 - root - DEBUG - get_md5sum_from_fname() fname=local_backups//etc_backups-hourly.tar.gz result=UNKNOWN
2024-09-04 12:26:05,731 - root - DEBUG - get_md5sum()            fname=local_backups//etc_backups-hourly.tar.gz result=a78068358bf6a8905a9a82a53d0e20b7
2024-09-04 12:26:05,731 - root - DEBUG - get_md5base64()         fname=local_backups//etc_backups-hourly.tar.gz result=p4BoNYv2qJBamoKlPQ4gtw==
2024-09-04 12:26:05,731 - root - DEBUG - (1) ALL_BACKUPS  : [{'file_path': 'local_backups//etc_backups-hourly.tar.gz', 'archive_name': 'etc_backups-hourly.tar.gz', 'dest_name': 'hourly.tar.gz/etc_backups-hourly.tar.gz', 'folder_type': 'hourly.tar.gz', 'md5sum_filename': 'UNKNOWN'}]
2024-09-04 12:26:05,731 - root - DEBUG - (1) UPLOAD_STATUS: {'local_backups//etc_backups-hourly.tar.gz': {'good_upload': [], 'md5sum_ok': False, 'md5sum': 'a78068358bf6a8905a9a82a53d0e20b7', 'md5base64': 'p4BoNYv2qJBamoKlPQ4gtw=='}}
2024-09-04 12:26:05,732 - root - DEBUG - BACKUP_SIZE: 18.4KiB
2024-09-04 12:26:05,732 - root - DEBUG - Connecting to Google...
2024-09-04 12:26:05,732 - google.auth._default - DEBUG - Checking None for explicit credentials as part of auth process...
2024-09-04 12:26:05,732 - google.auth._default - DEBUG - Checking Cloud SDK credentials as part of auth process...
2024-09-04 12:26:05,732 - google.auth._default - DEBUG - Cloud SDK credentials not found on disk; not using them
2024-09-04 12:26:05,733 - google.auth.transport._http_client - DEBUG - Making request: GET http://169.254.169.254
2024-09-04 12:26:08,737 - google.auth.compute_engine._metadata - WARNING - Compute Engine Metadata server unavailable on attempt 1 of 3. Reason: timed out
2024-09-04 12:26:09,668 - google.auth.transport._http_client - DEBUG - Making request: GET http://169.254.169.254
```


## Features
- File Locking: Ensures only one instance runs at a time.
-Parallel Processing: Uses threading to handle multiple uploads concurrently.
- Retry Mechanism: Retries operations that fail due to temporary issues.
- MD5 Checksum Verification: Ensures data integrity during uploads.
- Error Handling and Logging: Logs all activities, errors, and exceptions for troubleshooting.

## Logging
The script logs all activities to a file specified in the configuration (log_location). The log captures detailed information about file processing, uploads, retries, and errors.

## Troubleshooting
- Permission Errors: Ensure the Google Cloud Storage and Rackspace credentials have the necessary permissions.
- Configuration Errors: Verify the cloud_backup.conf file for correct syntax and valid parameters.
- Library Issues: Ensure all required libraries are installed and up to date.

## Contributing
If you'd like to contribute to this script, feel free to fork the repository and submit a pull request with your changes.

## License
This project is licensed under the MIT License.

## Contact
For any questions or issues, please contact the script's author.
