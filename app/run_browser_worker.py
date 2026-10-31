import os


def main():
    service_key = os.getenv("BROWSER_SERVICE_KEY", "")
    if not service_key:
        raise RuntimeError("BROWSER_SERVICE_KEY is required")
    preserved = {"BROWSER_SERVICE_KEY": service_key}
    for name in ("PATH", "HOME", "TMPDIR", "PYTHONPATH", "PLAYWRIGHT_BROWSERS_PATH", "PYTHONUNBUFFERED", "BROWSER_EGRESS_PROXY_URL"):
        if value := os.getenv(name):
            preserved[name] = value
    os.environ.clear()
    os.environ.update(preserved)

    import uvicorn

    uvicorn.run("app.browser_worker:app", host="0.0.0.0", port=8001)


if __name__ == "__main__":
    main()
