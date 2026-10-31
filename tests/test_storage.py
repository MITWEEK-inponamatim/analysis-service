import pytest

from app import storage


def test_accepts_object_inside_own_folder():
    assert storage.validate_object_path("user-1", "scan-1", "user-1/scan-1/page.png") == "user-1/scan-1/page.png"


@pytest.mark.parametrize(
    "path",
    [
        "user-2/scan-1/page.png",
        "user-1/scan-2/page.png",
        "user-1/scan-1/../../user-2/scan-1/page.png",
        "/user-1/scan-1/page.png",
        "user-1/scan-1/",
        "user-1/scan-1",
        "user-1\\scan-1\\page.png",
        "",
    ],
)
def test_rejects_foreign_or_unsafe_paths(path):
    with pytest.raises(storage.UnsafeStoragePath):
        storage.validate_object_path("user-1", "scan-1", path)


def test_rejects_unknown_bucket_before_network():
    with pytest.raises(storage.UnsafeStoragePath):
        import asyncio

        asyncio.run(storage.download_object("public-bucket", "user-1/scan-1/x.png", "user-1", "scan-1"))


def test_requires_user_and_scan_identifiers():
    with pytest.raises(storage.UnsafeStoragePath):
        storage.validate_object_path("", "scan-1", "user-1/scan-1/x.png")
