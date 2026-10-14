"""RU probe worker: fixed VLESS profiles, no backend-supplied commands or URLs."""
from __future__ import annotations

import asyncio
import base64
import http.client
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import ssl
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

VERSION = "1.0.0"
LOG = logging.getLogger("dns-guard-agent")
MAX_JOBS = 4
HEARTBEAT_PATH = Path("/tmp/dns-guard-agent-heartbeat")
PROFILE_FIELDS = {
    "port", "uuid", "transport", "security", "server_name", "public_key",
    "short_id", "flow", "fingerprint", "path", "host", "xhttp_mode",
}
FINGERPRINTS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}


class InvalidInput(ValueError):
    pass


def public_ipv4(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
        if ip.version != 4 or not ip.is_global or ip.is_multicast:
            raise ValueError
        return str(ip)
    except (ValueError, TypeError):
        raise InvalidInput("invalid_job") from None


def hostname(value: str, empty: bool = False) -> str:
    if value == "" and empty:
        return value
    if not isinstance(value, str) or len(value) > 253:
        raise InvalidInput("invalid_job")
    # ASCII hostnames/IP literals only; prohibit credentials, URLs and header injection.
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value):
        raise InvalidInput("invalid_job")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in value.split(".")):
        raise InvalidInput("invalid_job")
    return value


def bounded_string(value, limit: int = 256) -> str:
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise InvalidInput("invalid_job")
    return value


def validate_profile(data: dict) -> dict:
    if not isinstance(data, dict) or set(data) - PROFILE_FIELDS:
        raise InvalidInput("invalid_job")
    p = {"public_key": "", "short_id": "", "flow": "", "fingerprint": "chrome",
         "path": "/", "host": "", "xhttp_mode": "auto", **data}
    if type(p.get("port")) is not int or not 1 <= p["port"] <= 65535:
        raise InvalidInput("invalid_job")
    try:
        p["uuid"] = str(uuid.UUID(p["uuid"]))
    except (ValueError, TypeError, AttributeError, KeyError):
        raise InvalidInput("invalid_job") from None
    if p.get("transport") not in {"tcp", "xhttp"} or p.get("security") not in {"tls", "reality"}:
        raise InvalidInput("invalid_job")
    p["server_name"] = hostname(p.get("server_name"))
    p["host"] = hostname(p["host"], empty=True)
    if p["fingerprint"] not in FINGERPRINTS or p["xhttp_mode"] not in {"auto", "packet-up", "stream-up", "stream-one"}:
        raise InvalidInput("invalid_job")
    if p["flow"] not in {"", "xtls-rprx-vision"} or (p["transport"] == "xhttp" and p["flow"]):
        raise InvalidInput("invalid_job")
    p["path"] = bounded_string(p["path"], 2048)
    if not p["path"].startswith("/") or p["path"].startswith("//"):
        raise InvalidInput("invalid_job")
    p["short_id"] = bounded_string(p["short_id"], 16)
    if len(p["short_id"]) % 2 or not re.fullmatch(r"[a-fA-F0-9]*", p["short_id"]):
        raise InvalidInput("invalid_job")
    p["public_key"] = bounded_string(p["public_key"], 43)
    if p["security"] == "reality":
        try:
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", p["public_key"]) or len(base64.urlsafe_b64decode(p["public_key"] + "=")) != 32:
                raise ValueError
        except ValueError:
            raise InvalidInput("invalid_job") from None
    return p


def validate_job(job: dict) -> dict:
    if not isinstance(job, dict) or set(job) - {"job_id", "target_id", "ip", "profile", "timeout_seconds"}:
        raise InvalidInput("invalid_job")
    result = dict(job)
    for key in ("job_id", "target_id"):
        value = bounded_string(job.get(key), 128)
        if not value or not re.fullmatch(r"[A-Za-z0-9_.:-]+", value):
            raise InvalidInput("invalid_job")
    result["ip"] = public_ipv4(job.get("ip"))
    result["profile"] = validate_profile(job.get("profile"))
    if type(job.get("timeout_seconds")) is not int or not 1 <= job["timeout_seconds"] <= 30:
        raise InvalidInput("invalid_job")
    return result


def xray_config(job: dict, proxy_port: int) -> dict:
    job = validate_job(job)
    if type(proxy_port) is not int or not 1024 <= proxy_port <= 65535:
        raise InvalidInput("invalid_job")
    p = job["profile"]
    stream = {"network": "raw" if p["transport"] == "tcp" else "xhttp", "security": p["security"]}
    if p["security"] == "reality":
        stream["realitySettings"] = {"show": False, "serverName": p["server_name"],
            "fingerprint": p["fingerprint"], "password": p["public_key"], "shortId": p["short_id"]}
    else:
        stream["tlsSettings"] = {"serverName": p["server_name"], "allowInsecure": False, "fingerprint": p["fingerprint"]}
    if p["transport"] == "xhttp":
        stream["xhttpSettings"] = {"path": p["path"], "host": p["host"], "mode": p["xhttp_mode"]}
    user = {"id": p["uuid"], "encryption": "none"}
    if p["flow"]:
        user["flow"] = p["flow"]
    return {"log": {"loglevel": "none"},
        "inbounds": [{"tag": "probe-http", "listen": "127.0.0.1", "port": proxy_port,
                      "protocol": "http", "settings": {"allowTransparent": False}}],
        "outbounds": [{"tag": "target", "protocol": "vless", "settings": {"vnext": [
            {"address": job["ip"], "port": p["port"], "users": [user]}]}, "streamSettings": stream}]}


@dataclass(frozen=True)
class URL:
    raw: str
    scheme: str
    host: str
    port: int
    path: str


def parse_url(value: str, allow_http=False, base=False) -> URL:
    try:
        bounded_string(value, 2048)
        parts = urlsplit(value)
        if parts.scheme != "https" and not (allow_http and parts.scheme == "http"):
            raise ValueError
        if parts.username is not None or parts.password is not None or parts.fragment or not parts.hostname:
            raise ValueError
        host = hostname(parts.hostname)
        port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
        if base and parts.query:
            raise ValueError
        if not 1 <= port <= 65535:
            raise ValueError
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        return URL(value.rstrip("/") if base else value, parts.scheme, host, port, path)
    except (ValueError, TypeError):
        raise InvalidInput("invalid_settings") from None


def resolve_public(host: str, port: int, allow_private=False) -> list:
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise InvalidInput("control_unreachable")
    for _, _, _, _, address in addresses:
        ip = ipaddress.ip_address(address[0])
        if not allow_private and (not ip.is_global or ip.is_multicast):
            raise InvalidInput("control_unreachable")
    return addresses


class PinnedConnection(http.client.HTTPConnection):
    """Resolve once, validate every answer, connect to that address, preserve TLS SNI."""
    def __init__(self, url: URL, timeout: float, allow_private=False):
        super().__init__(url.host, url.port, timeout=timeout)
        self.url = url
        self.allow_private = allow_private

    def connect(self):
        addresses = resolve_public(self.host, self.port, self.allow_private)
        deadline = time.monotonic() + self.timeout
        last_error = None
        for family, kind, proto, _, address in addresses:
            sock = socket.socket(family, kind, proto)
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                sock.settimeout(remaining)
                sock.connect(address)
                if self.url.scheme == "https":
                    sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host)
                self.sock = sock
                return
            except (OSError, TimeoutError) as error:
                last_error = error
                sock.close()
        raise OSError("connection_failed") from last_error


def direct_request(url: URL, method="GET", payload=None, token=None, allow_private=False):
    # No redirect implementation; Authorization is sent only to this configured URL.
    connection = PinnedConnection(url, timeout=5, allow_private=allow_private)
    headers = {"User-Agent": "DNSGuard-Agent/" + VERSION, "Connection": "close"}
    body = None
    if payload is not None:
        body = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    try:
        connection.request(method, url.path, body=body, headers=headers)
        response = connection.getresponse()
        if payload is None:
            return 200 <= response.status < 400
        if not 200 <= response.status < 300:
            raise InvalidInput("backend_unreachable")
        raw = response.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise InvalidInput("backend_protocol_error")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise InvalidInput("backend_protocol_error")
        return value
    finally:
        connection.close()


@dataclass(frozen=True)
class Settings:
    control_plane_url: str
    token: str
    agent_id: str = "ru-1"
    xray_bin: str = "/usr/local/bin/xray"
    control_urls: tuple[str, ...] = ("https://ya.ru", "https://www.cloudflare.com/cdn-cgi/trace")
    probe_urls: tuple[str, ...] = ("https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204")
    allow_insecure_http: bool = False

    def __post_init__(self):
        parse_url(self.control_plane_url, self.allow_insecure_http, base=True)
        if not isinstance(self.token, str) or len(self.token) < 32 or re.search(r"[\s\x00-\x1f\x7f]", self.token):
            raise InvalidInput("invalid_settings")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", self.agent_id):
            raise InvalidInput("invalid_settings")
        if not os.path.isabs(self.xray_bin):
            raise InvalidInput("invalid_settings")
        for urls in (self.control_urls, self.probe_urls):
            if not 1 <= len(urls) <= 4:
                raise InvalidInput("invalid_settings")
            for value in urls:
                parse_url(value)  # The dev switch never permits insecure liveness/probe URLs.

    @classmethod
    def from_env(cls):
        defaults = cls.__dataclass_fields__
        return cls(control_plane_url=os.environ.get("CONTROL_PLANE_URL", ""),
                   token=os.environ.get("AGENT_TOKEN", ""), agent_id=os.environ.get("AGENT_ID", "ru-1"),
                   xray_bin=os.environ.get("XRAY_BIN", "/usr/local/bin/xray"),
                   control_urls=tuple(x.strip() for x in os.environ.get("CONTROL_URLS", ",".join(defaults["control_urls"].default)).split(",")),
                   probe_urls=tuple(x.strip() for x in os.environ.get("PROBE_URLS", ",".join(defaults["probe_urls"].default)).split(",")),
                   allow_insecure_http=os.environ.get("ALLOW_INSECURE_HTTP", "false").lower() == "true")


class Agent:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.stop = asyncio.Event()

    async def control_health(self) -> bool:
        async def check(value):
            try:
                return await asyncio.wait_for(asyncio.to_thread(direct_request, parse_url(value)), timeout=7)
            except Exception:
                return False
        return any(await asyncio.gather(*(check(value) for value in self.settings.control_urls)))

    async def api(self, path, body):
        url = parse_url(self.settings.control_plane_url.rstrip("/") + path, self.settings.allow_insecure_http)
        return await asyncio.wait_for(asyncio.to_thread(direct_request, url, "POST", body,
            self.settings.token, self.settings.allow_insecure_http), timeout=12)

    async def _tunnel_requests(self, port: int) -> bool:
        async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", trust_env=False,
                                     verify=True, follow_redirects=False, timeout=5) as client:
            # Configured destinations only. Never follow Location, read bodies, or attach tokens.
            per_url_timeout = max(0.5, 8 / len(self.settings.probe_urls))
            for value in self.settings.probe_urls:
                try:
                    async with asyncio.timeout(per_url_timeout):
                        async with client.stream("GET", value) as response:
                            if 200 <= response.status_code < 400:
                                return True
                except (httpx.HTTPError, TimeoutError):
                    continue
        return False

    async def _probe(self, job: dict) -> dict:
        started = time.monotonic()
        proc = None
        error = "tunnel_unreachable"
        try:
            with tempfile.TemporaryDirectory(prefix="dns-guard-") as directory:
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    port = reservation.getsockname()[1]
                path = Path(directory) / "config.json"
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as config_file:
                    json.dump(xray_config(job, port), config_file)
                try:
                    proc = await asyncio.create_subprocess_exec(self.settings.xray_bin, "run", "-config", str(path),
                        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                    async with asyncio.timeout(job["timeout_seconds"]):
                        # Loopback bind race or failed Xray startup is never an Internet success.
                        ready = False
                        for _ in range(40):
                            if proc.returncode is not None:
                                break
                            try:
                                _, writer = await asyncio.open_connection("127.0.0.1", port)
                                writer.close()
                                await writer.wait_closed()
                                ready = True
                                break
                            except OSError:
                                await asyncio.sleep(0.05)
                        if ready and await self._tunnel_requests(port):
                            return {"job_id": job["job_id"], "ok": True,
                                    "latency_ms": round((time.monotonic() - started) * 1000, 1), "error": None}
                        if not ready:
                            error = "xray_start_failed"
                finally:
                    if proc is not None and proc.returncode is None:
                        try:
                            proc.terminate()
                        except ProcessLookupError:
                            pass
                        try:
                            await asyncio.wait_for(proc.wait(), timeout=2)
                        except TimeoutError:
                            try:
                                proc.kill()
                            except ProcessLookupError:
                                pass
                            await proc.wait()
        except TimeoutError:
            error = "probe_timeout"
        except InvalidInput:
            error = "invalid_job"
        except OSError:
            error = "xray_start_failed"
        except Exception:
            error = "probe_failed"
        return {"job_id": job["job_id"], "ok": False, "latency_ms": None, "error": error}

    async def cycle(self) -> int:
        healthy = await self.control_health()
        poll_body = {"agent_id": self.settings.agent_id, "version": VERSION,
                     "control_ok": healthy, "control_error": None if healthy else "control_unreachable"}
        response = await self.api("/api/agent/poll", poll_body)
        # Healthcheck measures authenticated backend poll progress, including
        # correctly reported RU control outages. It never leases jobs itself.
        fd = os.open(HEARTBEAT_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as heartbeat:
            heartbeat.write(str(time.time()))
        delay = response.get("poll_after_seconds", 10)
        delay = min(60, max(1, delay)) if type(delay) is int else 10
        if not healthy:
            return delay
        jobs = response.get("jobs")
        if not isinstance(jobs, list) or len(jobs) > MAX_JOBS:
            raise InvalidInput("backend_protocol_error")
        validated = [validate_job(job) for job in jobs]
        if len({job["job_id"] for job in validated}) != len(validated) or len({job["target_id"] for job in validated}) != len(validated):
            raise InvalidInput("backend_protocol_error")
        if not validated:
            return delay
        results = await asyncio.gather(*(self._probe(job) for job in validated))
        # Submit only while direct controls are healthy. The batch is bounded below
        # backend heartbeat freshness; polling again here would lease extra jobs.
        healthy = await self.control_health()
        if healthy:
            await self.api("/api/agent/results", {"agent_id": self.settings.agent_id, "results": results})
        else:
            await self.api("/api/agent/poll", {**poll_body, "control_ok": False,
                "control_error": "control_unreachable"})
            LOG.warning("control_unreachable_results_suppressed")
        return delay

    async def run(self):
        while not self.stop.is_set():
            delay = 10
            try:
                delay = await self.cycle()
            except Exception:
                LOG.warning("poll_cycle_failed")
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=delay)
            except TimeoutError:
                pass


async def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        agent = Agent(Settings.from_env())
    except Exception:
        LOG.error("invalid_settings")
        return 2
    loop = asyncio.get_running_loop()
    task = asyncio.create_task(agent.run())
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, task.cancel)
    try:
        await task
    except asyncio.CancelledError:
        pass
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--healthcheck"]:
        try:
            age = time.time() - float(HEARTBEAT_PATH.read_text())
            raise SystemExit(0 if 0 <= age <= 180 else 1)
        except (OSError, ValueError):
            raise SystemExit(1)
    raise SystemExit(asyncio.run(main()))
