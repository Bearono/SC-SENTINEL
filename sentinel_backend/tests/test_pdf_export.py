import asyncio
import httpx
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select
from app.models.task import Task, TaskStatus, SourceType
from app.core.config import settings
import os

BASE_URL = "http://127.0.0.1:18000"
engine = create_async_engine(str(settings.DATABASE_URL))
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

async def test_pdf_export():
    # 1. Create a dummy completed task in DB
    async with AsyncSessionLocal() as session:
        task = Task(
            project_name="PDF-Export-Test",
            source_type=SourceType.GITHUB,
            source_path="https://github.com/test/test",
            status=TaskStatus.COMPLETED,
        )
        session.add(task)
        await session.commit()
        await session.refresh(task)
        task_id = str(task.id)
        print(f"Created completed task: {task_id}")

    # 2. Test the API
    async with httpx.AsyncClient() as client:
        url = f"{BASE_URL}/api/v1/tasks/{task_id}/export-pdf"
        print(f"Requesting {url}")
        response = await client.get(url)
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        assert response.headers["content-type"] == "application/pdf", "Expected application/pdf content type"
        assert b"%PDF" in response.content, "Response does not look like a PDF"
        
        with open("test_export.pdf", "wb") as f:
            f.write(response.content)
        print("PDF export API test passed! Saved test_export.pdf")

if __name__ == "__main__":
    asyncio.run(test_pdf_export())
