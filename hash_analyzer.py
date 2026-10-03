import hashlib
import os


def calculate_hashes(file_path):
    """
    Calculates MD5, SHA1, SHA256 and File Size
    """

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            data = f.read(4096)

            if not data:
                break

            md5.update(data)
            sha1.update(data)
            sha256.update(data)

    return {
        "Filename": os.path.basename(file_path),
        "File Size": f"{os.path.getsize(file_path):,} Bytes",
        "MD5": md5.hexdigest(),
        "SHA1": sha1.hexdigest(),
        "SHA256": sha256.hexdigest()
    }