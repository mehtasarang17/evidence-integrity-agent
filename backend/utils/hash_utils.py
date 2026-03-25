import hashlib
import os


def compute_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def compute_md5(file_path: str) -> str:
    """Compute MD5 hash of a file."""
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
    return md5.hexdigest()


def compute_all_hashes(file_path: str) -> dict:
    """Compute all supported hashes for a file."""
    return {
        "sha256": compute_sha256(file_path),
        "md5": compute_md5(file_path),
        "file_size": os.path.getsize(file_path),
    }


def verify_hash(file_path: str, expected_hash: str, algorithm: str = "sha256") -> bool:
    """Verify a file's hash against an expected value."""
    if algorithm == "sha256":
        actual = compute_sha256(file_path)
    elif algorithm == "md5":
        actual = compute_md5(file_path)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    return actual == expected_hash


def compute_perceptual_hash(file_path: str) -> str | None:
    """Compute a simple perceptual hash for images using average hash algorithm."""
    try:
        from PIL import Image
        img = Image.open(file_path).convert("L").resize((8, 8), Image.LANCZOS)
        pixels = list(img.getdata())
        avg = sum(pixels) / len(pixels)
        bits = "".join("1" if p > avg else "0" for p in pixels)
        return hex(int(bits, 2))[2:].zfill(16)
    except Exception:
        return None
