"""Build-time official release fetch, fail closed on missing/mismatched SHA256."""
import argparse
import hashlib
import io
from pathlib import Path
import re
import urllib.request
import zipfile

ASSETS = {"amd64": "Xray-linux-64.zip", "arm64": "Xray-linux-arm64-v8a.zip"}


def digest_sha256(text: str) -> str:
    matches = re.findall(r"(?im)^SHA(?:2-)?256\s*=\s*([0-9a-f]{64})\s*$", text)
    if len(matches) != 1:
        raise ValueError("invalid official SHA256 digest")
    return matches[0].lower()


def fetch(url: str) -> bytes:
    # Build-only downloader: redirects are necessary for GitHub release assets.
    with urllib.request.urlopen(url, timeout=120) as response:
        if not response.url.startswith("https://"):
            raise ValueError("insecure release redirect")
        return response.read(128 * 1024 * 1024)


def download(version: str, arch: str, destination: str):
    if not re.fullmatch(r"v\d+\.\d+\.\d+", version) or arch not in ASSETS:
        raise ValueError("unsupported Xray version or architecture")
    asset = ASSETS[arch]
    url = f"https://github.com/XTLS/Xray-core/releases/download/{version}/{asset}"
    expected = digest_sha256(fetch(url + ".dgst").decode("ascii"))
    archive = fetch(url)
    if hashlib.sha256(archive).hexdigest() != expected:
        raise ValueError("Xray release checksum mismatch")
    with zipfile.ZipFile(io.BytesIO(archive)) as package:
        binary = package.read("xray")
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(binary)
    target.chmod(0o755)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--arch", required=True, choices=ASSETS)
    parser.add_argument("--destination", required=True)
    args = parser.parse_args()
    download(args.version, args.arch, args.destination)
