import asyncio
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import AsyncMock, Mock, patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from probe_agent import Agent, InvalidInput, PinnedConnection, Settings, direct_request, parse_url, public_ipv4, validate_job, xray_config
from download_xray import digest_sha256, download


def job(identifier="job-1", target="target-1"):
    return {"job_id": identifier, "target_id": target, "ip": "8.8.8.8", "timeout_seconds": 15,
            "profile": {"port": 443, "uuid": "550e8400-e29b-41d4-a716-446655440000",
                        "transport": "tcp", "security": "reality", "server_name": "example.com",
                        "public_key": base64.urlsafe_b64encode(bytes(range(1, 33))).decode().rstrip("="),
                        "short_id": "aabb", "flow": "xtls-rprx-vision"}}


def settings():
    return Settings("https://guard.example.com", "x" * 32)


class ConfigTests(unittest.TestCase):
    def test_raw_reality_exact_ip_and_no_extra_outbounds(self):
        config = xray_config(job(), 12345)
        self.assertEqual(len(config["outbounds"]), 1)
        outbound = config["outbounds"][0]
        self.assertEqual(outbound["settings"]["vnext"][0]["address"], "8.8.8.8")
        self.assertEqual(outbound["streamSettings"]["network"], "raw")
        reality = outbound["streamSettings"]["realitySettings"]
        self.assertEqual(reality["password"], job()["profile"]["public_key"])
        self.assertNotIn("privateKey", reality)
        self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")

    def test_all_supported_transport_security_pairs(self):
        for transport in ("tcp", "xhttp"):
            for security in ("reality", "tls"):
                sample = job()
                sample["profile"].update(transport=transport, security=security, flow="")
                stream = xray_config(sample, 23456)["outbounds"][0]["streamSettings"]
                self.assertEqual(stream["security"], security)
                if transport == "xhttp":
                    self.assertEqual(stream["xhttpSettings"], {"path": "/", "host": "", "mode": "auto"})
                if security == "tls":
                    self.assertFalse(stream["tlsSettings"]["allowInsecure"])

    def test_ip_rejects_private_reserved_and_ipv6(self):
        for value in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "224.0.0.1", "192.0.2.1", "::1", "google.com"):
            with self.subTest(value=value), self.assertRaises(InvalidInput):
                public_ipv4(value)

    def test_profile_and_job_validation(self):
        changes = [({"port": 0}), {"port": True}, {"uuid": "nope"}, {"security": "none"},
                   {"transport": "ws"}, {"short_id": "abc"}, {"short_id": "zz"},
                   {"public_key": "bad"}, {"server_name": "evil\r\nHeader:x"},
                   {"fingerprint": "unsafe"}, {"path": "//host"}, {"xhttp_mode": "unsafe"},
                   {"raw_config": {"outbounds": []}}, {"transport": "xhttp", "flow": "xtls-rprx-vision"}]
        for changeset in changes:
            sample = job()
            sample["profile"].update(changeset)
            with self.subTest(changes=changeset), self.assertRaises(InvalidInput):
                validate_job(sample)
        for changeset in ({"timeout_seconds": 31}, {"command": "/bin/sh"}, {"ip": "127.0.0.1"}):
            with self.assertRaises(InvalidInput):
                validate_job({**job(), **changeset})

    def test_urls_and_environment_security(self):
        for value in ("http://example.com", "https://user:secret@example.com", "https://example.com/#x", "https://example.com:0", "https://example.com\n"):
            with self.subTest(url=value), self.assertRaises(InvalidInput):
                parse_url(value)
        self.assertEqual(parse_url("http://localhost:8080", allow_http=True).port, 8080)
        with self.assertRaises(InvalidInput):
            Settings("https://guard.example.com", "x" * 31)
        with self.assertRaises(InvalidInput):
            Settings("https://guard.example.com", "x" * 32, agent_id="bad:id")
        with self.assertRaises(InvalidInput):
            Settings("http://localhost:8080", "x" * 32, allow_insecure_http=True, control_urls=("http://ya.ru",))

    @patch("probe_agent.socket.getaddrinfo")
    def test_direct_checks_reject_private_dns_before_connect(self, resolve):
        resolve.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with patch("probe_agent.socket.socket") as sock, self.assertRaises(InvalidInput):
            PinnedConnection(parse_url("https://checks.example.com"), 5).connect()
        sock.assert_not_called()

    @patch("probe_agent.PinnedConnection")
    def test_backend_redirect_never_followed_or_token_forwarded(self, connection):
        conn = connection.return_value
        conn.getresponse.return_value.status = 302
        with self.assertRaises(InvalidInput):
            direct_request(parse_url("https://guard.example.com/api/agent/poll"), "POST", {}, "secret")
        self.assertEqual(conn.request.call_count, 1)
        self.assertEqual(conn.request.call_args.kwargs["headers"]["Authorization"], "Bearer secret")
        conn.close.assert_called_once()


class CycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_matching_results_and_excluded_targets_are_probed(self):
        agent = Agent(settings())
        jobs = [job("first", "excluded-target"), job("second", "healthy-target")]
        agent.control_health = AsyncMock(side_effect=[True, True])
        agent.api = AsyncMock(side_effect=[{"jobs": jobs, "poll_after_seconds": 10}, {"accepted": 2}])
        agent._probe = AsyncMock(side_effect=lambda value: {"job_id": value["job_id"], "ok": True, "latency_ms": 1, "error": None})
        self.assertEqual(await agent.cycle(), 10)
        self.assertEqual(agent.api.await_count, 2)
        self.assertEqual(agent.api.await_args_list[1].args[0], "/api/agent/results")
        results = agent.api.await_args_list[1].args[1]["results"]
        self.assertEqual([result["job_id"] for result in results], ["first", "second"])

    async def test_control_failure_suppresses_every_result_and_updates_health(self):
        agent = Agent(settings())
        agent.control_health = AsyncMock(side_effect=[True, False])
        agent.api = AsyncMock(side_effect=[{"jobs": [job()]}, {"jobs": []}])
        agent._probe = AsyncMock(return_value={"job_id": "job-1", "ok": False, "latency_ms": None, "error": "probe_timeout"})
        await agent.cycle()
        self.assertTrue(all(call.args[0] == "/api/agent/poll" for call in agent.api.await_args_list))
        self.assertFalse(agent.api.await_args_list[-1].args[1]["control_ok"])

    async def test_initial_outage_never_runs_jobs(self):
        agent = Agent(settings())
        agent.control_health = AsyncMock(return_value=False)
        agent.api = AsyncMock(return_value={"jobs": [job()]})
        agent._probe = AsyncMock()
        await agent.cycle()
        agent._probe.assert_not_awaited()

    async def test_duplicate_or_overlimit_jobs_reject_batch(self):
        for jobs in ([job(), job()], [job(str(i), str(i)) for i in range(5)]):
            agent = Agent(settings())
            agent.control_health = AsyncMock(return_value=True)
            agent.api = AsyncMock(return_value={"jobs": jobs})
            agent._probe = AsyncMock()
            with self.assertRaises(InvalidInput):
                await agent.cycle()
            agent._probe.assert_not_awaited()

    async def test_process_and_private_config_cleaned_on_error(self):
        agent = Agent(settings())
        process = Mock(returncode=None, terminate=Mock(), kill=Mock(), wait=AsyncMock(return_value=0))
        inspected = []

        async def spawn(*command, **kwargs):
            path = Path(command[-1])
            inspected.append(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text())["outbounds"][0]["settings"]["vnext"][0]["address"], "8.8.8.8")
            self.assertEqual(kwargs["stderr"], asyncio.subprocess.DEVNULL)
            return process

        writer = Mock(close=Mock(), wait_closed=AsyncMock())
        with patch("probe_agent.asyncio.create_subprocess_exec", side_effect=spawn), patch("probe_agent.asyncio.open_connection", AsyncMock(return_value=(None, writer))):
            agent._tunnel_requests = AsyncMock(side_effect=RuntimeError("private uuid token raw config"))
            result = await agent._probe(job())
        self.assertEqual(result["error"], "probe_failed")
        self.assertIsNone(result["latency_ms"])
        process.terminate.assert_called_once()
        process.wait.assert_awaited_once()
        self.assertFalse(inspected[0].exists())
        self.assertFalse(inspected[0].parent.exists())

    async def test_process_killed_if_termination_times_out(self):
        agent = Agent(settings())
        process = Mock(returncode=None, terminate=Mock(), kill=Mock(), wait=AsyncMock(side_effect=[TimeoutError(), 0]))
        writer = Mock(close=Mock(), wait_closed=AsyncMock())
        agent._tunnel_requests = AsyncMock(return_value=False)
        with patch("probe_agent.asyncio.create_subprocess_exec", AsyncMock(return_value=process)), patch("probe_agent.asyncio.open_connection", AsyncMock(return_value=(None, writer))):
            result = await agent._probe(job())
        self.assertEqual(result["error"], "tunnel_unreachable")
        process.kill.assert_called_once()

    async def test_proxy_is_local_has_no_auth_and_never_redirects(self):
        agent = Agent(settings())
        response = Mock(status_code=204)
        stream = AsyncMock()
        stream.__aenter__.return_value = response
        client = Mock(stream=Mock(return_value=stream))
        manager = AsyncMock()
        manager.__aenter__.return_value = client
        with patch("probe_agent.httpx.AsyncClient", return_value=manager) as constructor:
            self.assertTrue(await agent._tunnel_requests(12345))
        self.assertEqual(constructor.call_args.kwargs["proxy"], "http://127.0.0.1:12345")
        self.assertFalse(constructor.call_args.kwargs["trust_env"])
        self.assertFalse(constructor.call_args.kwargs["follow_redirects"])
        self.assertTrue(constructor.call_args.kwargs["verify"])
        self.assertEqual(client.stream.call_args.args, ("GET", settings().probe_urls[0]))

    async def test_transient_cycle_failure_does_not_exit(self):
        agent = Agent(settings())

        async def fail():
            agent.stop.set()
            raise OSError("private details")

        agent.cycle = AsyncMock(side_effect=fail)
        with self.assertLogs("dns-guard-agent", level="WARNING") as logs:
            await agent.run()
        self.assertEqual(logs.output, ["WARNING:dns-guard-agent:poll_cycle_failed"])


class DownloaderTests(unittest.TestCase):
    def test_official_digest_format(self):
        value = "a" * 64
        self.assertEqual(digest_sha256("MD5= 123\nSHA2-256= " + value + "\nSHA2-512= " + "b" * 128), value)
        self.assertEqual(digest_sha256("SHA256= " + value), value)
        with self.assertRaises(ValueError):
            digest_sha256("SHA1= " + value)

    @patch("download_xray.fetch")
    def test_checksum_mismatch_never_writes_executable(self, fetch):
        fetch.side_effect = [("SHA2-256= " + "a" * 64).encode(), b"malicious"]
        with self.assertRaises(ValueError), patch("download_xray.Path.write_bytes") as write:
            download("v26.3.27", "amd64", "/tmp/unused-agent-test")
        write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
