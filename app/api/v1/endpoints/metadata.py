"""
Metadata Intelligence Engine — Commit 1: temporary extraction endpoint.

Exposes a SINGLE temporary endpoint that accepts an uploaded asset and returns
the normalized metadata JSON produced by the extraction service. This endpoint
performs extraction ONLY — nothing is persisted, and no other subsystem
(registry, certificates, verify, trust scoring) is touched.
"""
from fastapi import APIRouter, UploadFile, File

from app.services.metadata_extraction import extract_metadata_service

router = APIRouter(prefix="/metadata", tags=["metadata"])


@router.post("/extract")
async def extract_metadata(file: UploadFile = File(...)):
    """
    Extract comprehensive, normalized metadata from an uploaded asset.

    Input:  multipart/form-data file upload.
    Output: structured metadata JSON (see MetadataExtractionService).

    The service never raises on malformed / corrupt / empty input; extraction
    problems are reported inside the ``warnings`` field of the response.
    """
    data = await file.read()
    return extract_metadata_service(
        data,
        filename=file.filename,
        mime_type=file.content_type,
    )
