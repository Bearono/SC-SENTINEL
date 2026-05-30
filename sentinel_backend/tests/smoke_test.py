"""
SENTINEL API Integration Smoke Test Script
This script performs an automated integration test against the running backend server.
It tests all 6 core APIs (HTTP and WebSocket) and checks global response wrapping.
"""
import io
import zipfile
import asyncio
import httpx
import websockets
import json

BASE_URL = "http://127.0.0.1:18000"
WS_URL = "ws://127.0.0.1:18000"

# Create a dummy zip file in-memory for testing
def create_dummy_zip():
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("main.c", "#include <stdio.h>\nint main() { printf(\"Hello World\\n\"); return 0; }\n")
    zip_buffer.seek(0)
    return zip_buffer.getvalue()

async def test_health():
    print("\n[Test 1] Testing GET /health...")
    async with httpx.AsyncClient(trust_env=False) as client:
        response = await client.get(f"{BASE_URL}/health")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert data["status"] == "ok", "Expected status to be 'ok'"
        print("-> Health check passed:", data)

async def test_create_task_zip():
    print("\n[Test 2] Testing POST /api/v1/tasks (ZIP source)...")
    zip_data = create_dummy_zip()
    
    async with httpx.AsyncClient(trust_env=False) as client:
        files = {"file": ("test_project.zip", zip_data, "application/zip")}
        data = {
            "project_name": "SmokeTest-ZIP",
            "source_type": "zip",
            "target_vulns": '["UAF", "Double_Free"]',
            "is_dynamic": "true"
        }
        response = await client.post(f"{BASE_URL}/api/v1/tasks", data=data, files=files)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        res_json = response.json()
        assert res_json["code"] == 200, f"Expected wrapped code 200, got {res_json['code']}"
        assert res_json["message"] == "审计任务创建成功，等待调度执行"
        task_data = res_json["data"]
        assert task_data["project_name"] == "SmokeTest-ZIP"
        assert task_data["status"] == "pending"
        assert "id" in task_data
        
        print("-> Create ZIP task passed. Task ID:", task_data["id"])
        return task_data["id"]

async def test_create_task_github():
    print("\n[Test 3] Testing POST /api/v1/tasks (GitHub source)...")
    async with httpx.AsyncClient(trust_env=False) as client:
        data = {
            "project_name": "SmokeTest-GitHub",
            "source_type": "github",
            "source_path": "https://github.com/example/c-project.git",
            "target_vulns": '["Buffer_Overflow"]',
            "is_dynamic": "false"
        }
        response = await client.post(f"{BASE_URL}/api/v1/tasks", data=data)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        res_json = response.json()
        assert res_json["code"] == 200, f"Expected wrapped code 200, got {res_json['code']}"
        task_data = res_json["data"]
        assert task_data["project_name"] == "SmokeTest-GitHub"
        assert task_data["status"] == "pending"
        
        print("-> Create GitHub task passed. Task ID:", task_data["id"])
        return task_data["id"]

async def test_list_tasks():
    print("\n[Test 4] Testing GET /api/v1/tasks (List & Pagination)...")
    async with httpx.AsyncClient(trust_env=False) as client:
        response = await client.get(f"{BASE_URL}/api/v1/tasks?page=1&size=5")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        res_json = response.json()
        assert res_json["code"] == 200, f"Expected wrapped code 200, got {res_json['code']}"
        data = res_json["data"]
        assert "total" in data
        assert "items" in data
        assert isinstance(data["items"], list)
        assert len(data["items"]) >= 2, f"Expected at least 2 items, got {len(data['items'])}"
        
        print(f"-> List tasks passed. Total tasks: {data['total']}. Items in this page: {len(data['items'])}")

async def test_get_task_status(task_id):
    print(f"\n[Test 5] Testing GET /api/v1/tasks/{task_id} (Task status)...")
    async with httpx.AsyncClient(trust_env=False) as client:
        response = await client.get(f"{BASE_URL}/api/v1/tasks/{task_id}")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        res_json = response.json()
        assert res_json["code"] == 200
        task_data = res_json["data"]
        assert task_data["id"] == task_id
        assert "status" in task_data
        
        print(f"-> Get task status passed. Status: {task_data['status']}")

async def test_websocket_progress(task_id):
    print(f"\n[Test 6] Testing WS /api/v1/ws/tasks/{task_id}/progress (WebSocket)...")
    uri = f"{WS_URL}/api/v1/ws/tasks/{task_id}/progress"
    
    async with websockets.connect(uri) as ws:
        # 1. Check handshake message
        msg = await ws.recv()
        msg_json = json.loads(msg)
        assert msg_json["stage"] == "connected"
        assert msg_json["percent"] == 0
        assert "已成功连接" in msg_json["message"]
        print("-> WebSocket handshake message received:", msg_json)
        
        # 2. Check ping-pong heartbeat
        await ws.send("ping")
        resp = await ws.recv()
        assert resp == "pong", f"Expected 'pong', got {resp}"
        print("-> WebSocket heartbeat ping-pong passed.")

async def test_cancel_task(task_id):
    print(f"\n[Test 7] Testing POST /api/v1/tasks/{task_id}/cancel...")
    async with httpx.AsyncClient(trust_env=False) as client:
        response = await client.post(f"{BASE_URL}/api/v1/tasks/{task_id}/cancel")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        res_json = response.json()
        assert res_json["code"] == 200
        assert "已强制终止" in res_json["message"]
        
        # Verify status is updated to failed
        status_resp = await client.get(f"{BASE_URL}/api/v1/tasks/{task_id}")
        task_data = status_resp.json()["data"]
        assert task_data["status"] == "failed", f"Expected task status 'failed', got '{task_data['status']}'"
        print("-> Cancel task passed.")

async def test_get_report_non_completed(task_id):
    print(f"\n[Test 8] Testing GET /api/v1/tasks/{task_id}/report (Expected failure case)...")
    async with httpx.AsyncClient(trust_env=False) as client:
        response = await client.get(f"{BASE_URL}/api/v1/tasks/{task_id}/report")
        assert response.status_code == 200, f"Expected 200 HTTP status, got {response.status_code}"
        
        res_json = response.json()
        assert res_json["code"] == 400, f"Expected business code 400, got {res_json['code']}"
        assert "任务尚未完成" in res_json["message"]
        print("-> Get report fail-safe check passed:", res_json["message"])

async def main():
    print("Starting SENTINEL API Integration Tests...")
    try:
        await test_health()
        task_id_zip = await test_create_task_zip()
        task_id_github = await test_create_task_github()
        await test_list_tasks()
        await test_get_task_status(task_id_zip)
        await test_websocket_progress(task_id_zip)
        await test_cancel_task(task_id_zip)
        await test_get_report_non_completed(task_id_zip)
        print("\nAll tests passed successfully! The API layer is solid and correct.")
    except AssertionError as e:
        print("\nTest assertion failed:", str(e))
    except Exception as e:
        print("\nTest execution failed with error:", str(e))

if __name__ == "__main__":
    asyncio.run(main())
