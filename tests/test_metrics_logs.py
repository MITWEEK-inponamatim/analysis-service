import time

from app.logs import RedactingFilter, configure_logging, redact
from app.metrics import Metrics


def test_counters_and_labels_are_aggregated():
    metrics = Metrics()
    metrics.inc("jobs_total", type="url")
    metrics.inc("jobs_total", type="url")
    metrics.inc("jobs_total", type="image")
    counters = metrics.snapshot()["counters"]
    assert counters['jobs_total{type="url"}'] == 2
    assert counters['jobs_total{type="image"}'] == 1


def test_duration_summary_tracks_count_avg_and_max():
    metrics = Metrics()
    metrics.observe("job_seconds", 0.4, type="url")
    metrics.observe("job_seconds", 1.6, type="url")
    summary = metrics.snapshot()["durations"]['job_seconds{type="url"}']
    assert summary["count"] == 2
    assert summary["avg_ms"] == 1000
    assert summary["max_ms"] == 1600


def test_timer_records_a_duration():
    metrics = Metrics()
    with metrics.timer("work", step="ocr"):
        time.sleep(0.01)
    assert metrics.snapshot()["durations"]['work{step="ocr"}']["count"] == 1


def test_reset_clears_state():
    metrics = Metrics()
    metrics.inc("x")
    metrics.reset()
    assert metrics.snapshot() == {"counters": {}, "durations": {}}


def test_redacts_known_credential_shapes():
    message = "key sk-abcdefghijklmnop token=supersecret Bearer abcdefghijkl postgres://user:pass@host/db " + "a" * 64
    cleaned = redact(message)
    assert "sk-abcdefghijklmnop" not in cleaned
    assert "supersecret" not in cleaned
    assert "abcdefghijkl" not in cleaned
    assert "user:pass" not in cleaned
    assert "a" * 64 not in cleaned


def test_redacting_filter_rewrites_the_record():
    import logging

    record = logging.LogRecord("test", logging.INFO, __file__, 1, "token=abc123", None, None)
    assert RedactingFilter().filter(record) is True
    assert "abc123" not in record.getMessage()


def test_configure_logging_is_idempotent():
    configure_logging()
    handlers = len(logging_root_handlers())
    configure_logging()
    assert len(logging_root_handlers()) == handlers


def logging_root_handlers():
    import logging

    return logging.getLogger().handlers
