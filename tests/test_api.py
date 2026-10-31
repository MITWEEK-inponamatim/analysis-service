from fastapi.testclient import TestClient
from app.main import app, jobs

def test_internal_message_job(monkeypatch):
    async def no_op(*_args, **_kwargs):
        return None

    async def update_local(job_id, **fields):
        jobs[job_id].update(fields)

    monkeypatch.setenv("SERVICE_API_KEY", "unit-test-service-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr("app.main.save_job", no_op)
    monkeypatch.setattr("app.main.update_job", update_local)
    jobs.clear()
    client = TestClient(app)
    denied = client.get("/internal/v1/health")
    assert denied.status_code == 401
    headers = {"X-Service-Key": "unit-test-service-key"}
    created = client.post("/internal/v1/jobs", headers=headers, json={
        "scan_id": "local-scan-id", "user_id": "local-user-id", "type": "message",
        "input": {"text": "Selamat, Anda mendapat hadiah. Kirim OTP sekarang."},
    })
    assert created.status_code == 202
    job = client.get(f"/internal/v1/jobs/{created.json()['job_id']}", headers=headers)
    assert job.status_code == 200
    assert job.json()["status"] == "completed"
    assert job.json()["report"]["risk"]["level"] == "medium"
