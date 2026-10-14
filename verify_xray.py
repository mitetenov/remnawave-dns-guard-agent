"""Parse generated profiles with the actual pinned binary; never connect to a node."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile

from probe_agent import xray_config


def main():
    binary = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
    validated = 0
    with tempfile.TemporaryDirectory(prefix="dns-guard-selftest-") as directory:
        for transport in ("tcp", "xhttp"):
            for security in ("tls", "reality"):
                modes = ("auto", "packet-up", "stream-up", "stream-one") if transport == "xhttp" else ("auto",)
                for mode in modes:
                    job = {"job_id": "synthetic", "target_id": "synthetic", "ip": "8.8.8.8", "timeout_seconds": 15,
                        "profile": {"port": 443, "uuid": "550e8400-e29b-41d4-a716-446655440000",
                            "transport": transport, "security": security, "server_name": "example.com",
                            "public_key": base64.urlsafe_b64encode(bytes(range(1, 33))).decode().rstrip("="),
                            "short_id": "aabb", "flow": "xtls-rprx-vision" if transport == "tcp" else "",
                            "xhttp_mode": mode}}
                    path = Path(directory) / "config.json"
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, "w") as config_file:
                        json.dump(xray_config(job, 18080), config_file)
                    result = subprocess.run([binary, "run", "-test", "-config", str(path)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
                    if result.returncode:
                        raise SystemExit(f"Xray profile self-test failed: {transport}/{security}/{mode}")
                    validated += 1
    print(f"Xray accepted {validated} generated synthetic profiles (config validation only)")


if __name__ == "__main__":
    main()
