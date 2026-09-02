from fastapi import HTTPException, UploadFile


DEFAULT_CHUNK_BYTES = 1024 * 1024


async def read_upload_limited(
    file: UploadFile,
    *,
    max_mb: int,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
) -> bytes:
    """Read an UploadFile without allowing unbounded in-memory growth.

    The stream is consumed in fixed-size chunks and rejected as soon as the
    configured byte limit is exceeded. Callers receive the same bytes object
    they previously used, but oversized requests never need to be fully read
    into application memory first.
    """
    max_bytes = int(max_mb) * 1024 * 1024
    if max_bytes <= 0:
        raise RuntimeError("Upload size limit must be greater than zero.")

    parts: list[bytes] = []
    total = 0

    while True:
        chunk = await file.read(chunk_bytes)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum upload size is {max_mb} MB.",
            )
        parts.append(chunk)

    return b"".join(parts)
