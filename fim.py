import hashlib
import json
import time
import logging
import requests
import os
from pathlib import Path
from datetime import datetime
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

# =====================================================
# LOAD ENV VARIABLES
# =====================================================
load_dotenv()

# =====================================================
# CONFIGURATION
# =====================================================
FILES_FOLDER = Path("files")
BASELINE_FILE = Path("baseline.json")
LOG_FILE = Path("fim.log")
INTERVAL = 10  # seconds

# Jira (from .env)
JIRA_URL = os.getenv("JIRA_URL")
JIRA_EMAIL = os.getenv("JIRA_EMAIL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY")
ISSUE_TYPE = os.getenv("JIRA_ISSUE_TYPE")
PRIORITY = os.getenv("JIRA_PRIORITY")

# =====================================================
# LOGGING CONFIGURATION (Console + File)
# =====================================================
LOG_FILE.parent.mkdir(exist_ok=True)

logger = logging.getLogger("FIM")
logger.setLevel(logging.INFO)

log_format = logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s"
)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_format)

# File handler
file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
file_handler.setFormatter(log_format)

if not logger.handlers:
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

# =====================================================
# HASH FUNCTION
# =====================================================
def calculate_hash(file_path: Path) -> str:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

# =====================================================
# BASELINE FUNCTIONS
# =====================================================
def create_baseline():
    baseline = {}
    for file in FILES_FOLDER.glob("*"):
        if file.is_file():
            baseline[file.name] = calculate_hash(file)

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)

    logger.info("Baseline created successfully")

def load_baseline():
    with open(BASELINE_FILE, "r") as f:
        return json.load(f)

# =====================================================
# JIRA ISSUE CREATION
# =====================================================
def create_jira_issue(alert: dict):
    url = f"{JIRA_URL}/rest/api/3/issue"
    auth = HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)

    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": f"FIM Alert: {alert['event']} - {alert['filename']}",
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    f"Event: {alert['event']}\n"
                                    f"File: {alert['filename']}\n"
                                    f"Old Hash: {alert['old_hash']}\n"
                                    f"New Hash: {alert.get('new_hash', 'N/A')}\n"
                                    f"Timestamp: {alert['timestamp']}"
                                )
                            }
                        ]
                    }
                ]
            },
            "issuetype": {"name": ISSUE_TYPE},
            "priority": {"name": PRIORITY}
        }
    }

    response = requests.post(url, json=payload, auth=auth)

    if response.status_code == 201:
        logger.warning("Jira ticket created for %s", alert["filename"])
    else:
        logger.error(
            "Failed to create Jira ticket | Status: %s | Response: %s",
            response.status_code,
            response.text
        )

# =====================================================
# MONITORING LOGIC
# =====================================================
def monitor():
    baseline = load_baseline()
    logger.info("FIM monitoring started")

    while True:
        current_files = {}

        # Scan current files
        for file in FILES_FOLDER.glob("*"):
            if file.is_file():
                current_files[file.name] = calculate_hash(file)

        # 1. FILE MODIFIED
        for filename, old_hash in baseline.items():
            if filename in current_files:
                if current_files[filename] != old_hash:
                    alert = {
                        "event": "FILE_MODIFIED",
                        "filename": filename,
                        "old_hash": old_hash,
                        "new_hash": current_files[filename],
                        "timestamp": datetime.now().isoformat()
                    }
                    logger.critical("File modified: %s", filename)
                    create_jira_issue(alert)

        # 2. FILE DELETED
        for filename in baseline:
            if filename not in current_files:
                alert = {
                    "event": "FILE_DELETED",
                    "filename": filename,
                    "old_hash": baseline[filename],
                    "new_hash": "N/A",
                    "timestamp": datetime.now().isoformat()
                }
                logger.critical("File deleted: %s", filename)
                create_jira_issue(alert)

        # 3. FILE CREATED
        for filename, new_hash in current_files.items():
            if filename not in baseline:
                alert = {
                    "event": "FILE_CREATED",
                    "filename": filename,
                    "old_hash": "N/A",
                    "new_hash": new_hash,
                    "timestamp": datetime.now().isoformat()
                }
                logger.critical("New file created: %s", filename)
                create_jira_issue(alert)

        time.sleep(INTERVAL)

# =====================================================
# MAIN
# =====================================================
if __name__ == "__main__":
    FILES_FOLDER.mkdir(exist_ok=True)

    if not BASELINE_FILE.exists():
        create_baseline()

    monitor()
