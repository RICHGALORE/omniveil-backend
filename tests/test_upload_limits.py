import asyncio
from io import BytesIO

import pytest
from fastapi import HTTPException, UploadFile

from app.utils.upload_limits import read_upload_limited


def _upload(data: bytes) -> UploadFile:
    return UploadFile(filename="bounded.bin", file=BytesIO(data))


def test_bounded_reader_accepts_file_at_limit():
    payload = b"a" * (1024 * 1024)
    result = asyncio.run(
        read_upload_limited(
            _upload(payload),
            max_mb=1,
            chunk_bytes=64 * 1024,
        )
    )
    assert result == payload


def test_bounded_reader_rejects_as_soon_as_limit_is_exceeded():
    payload = b"a" * (1024 * 1024 + 1)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            read_upload_limited(
                _upload(payload),
                max_mb=1,
                chunk_bytes=64 * 1024,
            )
        )

    assert exc.value.status_code == 413
    assert "Maximum upload size is 1 MB" in str(exc.value.detail)


def test_bounded_reader_rejects_invalid_limit_configuration():
    with pytest.raises(RuntimeError):
        asyncio.run(read_upload_limited(_upload(b"data"), max_mb=0))
