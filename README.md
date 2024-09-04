# Backup Automation Script

## Overview

This Python script automates the process of uploading backup files to Google Cloud Storage and Rackspace Cloud Files. It includes mechanisms for file locking, retrying failed operations, MD5 checksum verification for data integrity, and detailed logging.

## Requirements

- **Python 3.x**  
- Required libraries: `google-cloud-storage`, `pyrax`, `retrying`, `requests`

Install dependencies with:

```bash
pip install google-cloud-storage pyrax retrying requests
```

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
