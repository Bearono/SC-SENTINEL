import httpx
import time
import zipfile
import os
import sys
from pathlib import Path

def create_dummy_zip():
    os.makedirs("dummy_test", exist_ok=True)
    with open("dummy_test/main.c", "w") as f:
        f.write("#include <stdio.h>\\nint main() { printf(\"Hello\"); return 0; }\\n")
    with open("dummy_test/CMakeLists.txt", "w") as f:
        f.write("cmake_minimum_required(VERSION 3.10)\\nproject(Dummy)\\nadd_executable(dummy main.c)\\n")
    
    zip_name = "dummy_test.zip"
    with zipfile.ZipFile(zip_name, 'w') as zipf:
        for root, _, files in os.walk("dummy_test"):
            for file in files:
                zipf.write(os.path.join(root, file), arcname=file)
    return zip_name

def run_test():
    zip_file = create_dummy_zip()
    url = "http://127.0.0.1:18000/api/v1/tasks"
    
    print("1. Submitting Task...")
    with open(zip_file, "rb") as f:
        files = {"file": (zip_file, f, "application/zip")}
        data = {
            "project_name": "Dummy-Test-Project",
            "source_type": "zip",
            "is_dynamic": "false"  # Only test Phase 1 and 2 for fast feedback
        }
        resp = httpx.post(url, data=data, files=files)
        resp.raise_for_status()
        resp_data = resp.json()
        print("Submit Response:", resp_data)
        task_id = resp_data["data"]["id"]
        
    print(f"\\n2. Polling Task Status for {task_id}...")
    while True:
        status_resp = httpx.get(f"{url}/{task_id}")
        status_resp.raise_for_status()
        status_data = status_resp.json()["data"]
        status = status_data["status"]
        print(f"Current Status: {status}")
        
        if status in ["completed", "failed"]:
            break
        time.sleep(2)
        
    if status == "failed":
        print("Task failed!")
        sys.exit(1)
        
    print("\\n3. Fetching Final Report...")
    report_resp = httpx.get(f"{url}/{task_id}/report")
    report_resp.raise_for_status()
    print("Report Data:", report_resp.json()["data"])
    
    print("\\n4. Exporting PDF...")
    pdf_resp = httpx.get(f"{url}/{task_id}/export-pdf")
    pdf_resp.raise_for_status()
    with open("dummy_report.pdf", "wb") as f:
        f.write(pdf_resp.content)
    print(f"PDF saved to dummy_report.pdf ({len(pdf_resp.content)} bytes)")
    
    print("\\nALL TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_test()
