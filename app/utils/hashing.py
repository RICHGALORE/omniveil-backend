import hashlib

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def blake3_bytes(data: bytes) -> str:
    try:
        import blake3
        return blake3.blake3(data).hexdigest()
    except:
        return hashlib.sha256(data).hexdigest()

def phash_image(data: bytes):
    try:
        import imagehash
        from PIL import Image
        import io
        return str(imagehash.phash(Image.open(io.BytesIO(data))))
    except:
        return None

def generate_omni_id(tenant_id: str, sha256: str) -> str:
    tag = hashlib.md5(tenant_id.encode()).hexdigest()[:8].upper()
    sig = hashlib.sha256(f"{tenant_id}:{sha256}".encode()).hexdigest()[:16].upper()
    return f"OV-{tag}{sig}"
