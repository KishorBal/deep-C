import subprocess
import uuid
import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


def run_scan(apk_path: str, ai_review: bool):
    scan_id = str(uuid.uuid4())
    result_file = os.path.join(BASE_DIR, "deepc_result.json")

    cmd = ["python3", "deepc.py", "-a", apk_path]

    if ai_review:
        cmd.append("--ai-review")

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=BASE_DIR
    )

    stdout, _ = process.communicate()

    results = {}
    if os.path.exists(result_file):
        with open(result_file, "r") as f:
            results = json.load(f)

    return {
        "scan_id": scan_id,
        "stdout": stdout,
        "results": results
    }
