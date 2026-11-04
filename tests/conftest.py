"""Test isolation: unit tests must never call OpenAI, Supabase, or threat-intel services.

``app.main`` loads ``analysis-service/.env`` at import time. Values that already exist in the
environment are not overridden by ``load_dotenv``, so pinning these to empty strings here keeps
every test offline even when a real ``.env`` is present.
"""

import os

OFFLINE_KEYS = (
    "OPENAI_API_KEY",
    "SAFE_BROWSING_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "EXA_API_KEY",
    "MOBSF_URL",
    "MOBSF_API_KEY",
    "SUPABASE_URL",
    "SUPABASE_SECRET_KEY",
    "DATABASE_URL_SESSION",
    "FILE_WORKER_URL",
    "SERVICE_API_KEY",
    "RETENTION_ENABLED",
)

for _key in OFFLINE_KEYS:
    os.environ[_key] = ""
