import random
import socket

import httpx
import pytest

from triage.http import HttpClient, HttpError


def scripted(*steps):
    """A MockTransport handler that plays `steps` in order; a callable step raises or returns."""
    calls = []
    remaining = list(steps)

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        step = remaining.pop(0) if len(remaining) > 1 else remaining[0]
        return step(request) if callable(step) else step

    return handler, calls


def make_client(handler, **kwargs):
    sleeps = []
    client = HttpClient(
        transport=httpx.MockTransport(handler), sleep=sleeps.append, rng=random.Random(0), **kwargs
    )
    return client, sleeps


def timeout(request):
    raise httpx.ReadTimeout("timed out", request=request)


def test_network_is_blocked_in_tests():
    with pytest.raises(RuntimeError, match="network access is disabled"):
        socket.create_connection(("example.com", 443), timeout=1)


def test_retries_server_errors_then_succeeds():
    handler, calls = scripted(
        httpx.Response(503), httpx.Response(503), httpx.Response(200, text="ok")
    )
    client, sleeps = make_client(handler)
    assert client.get("https://feeds.example/x").text == "ok"
    assert len(calls) == 3
    assert len(sleeps) == 2
    assert sleeps[1] > sleeps[0]


def test_retries_timeouts():
    handler, calls = scripted(timeout, httpx.Response(200, text="ok"))
    client, sleeps = make_client(handler)
    assert client.get("https://feeds.example/x").status_code == 200
    assert len(calls) == 2
    assert len(sleeps) == 1


def test_honours_retry_after():
    handler, _ = scripted(
        httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(200, text="ok")
    )
    client, sleeps = make_client(handler)
    client.get("https://feeds.example/x")
    assert sleeps == [7.0]


def test_retry_after_is_capped():
    handler, _ = scripted(
        httpx.Response(429, headers={"Retry-After": "3600"}), httpx.Response(200, text="ok")
    )
    client, sleeps = make_client(handler, max_backoff=30.0)
    client.get("https://feeds.example/x")
    assert sleeps == [30.0]


def test_does_not_retry_client_errors():
    handler, calls = scripted(httpx.Response(404))
    client, sleeps = make_client(handler)
    with pytest.raises(HttpError, match="404") as excinfo:
        client.get("https://feeds.example/x")
    assert excinfo.value.status_code == 404
    assert len(calls) == 1
    assert sleeps == []


def test_gives_up_after_max_attempts():
    handler, calls = scripted(httpx.Response(503))
    client, sleeps = make_client(handler, max_attempts=3)
    with pytest.raises(HttpError, match="503"):
        client.get("https://feeds.example/x")
    assert len(calls) == 3
    assert len(sleeps) == 2


def test_transport_errors_are_reported_after_retries():
    handler, calls = scripted(timeout)
    client, _ = make_client(handler, max_attempts=2)
    with pytest.raises(HttpError, match="ReadTimeout"):
        client.get("https://feeds.example/x")
    assert len(calls) == 2


def test_backoff_is_capped():
    handler, _ = scripted(httpx.Response(503))
    client, sleeps = make_client(handler, max_attempts=8, backoff_base=1.0, max_backoff=5.0)
    with pytest.raises(HttpError):
        client.get("https://feeds.example/x")
    assert max(sleeps) <= 5.0


def test_timeouts_are_configured():
    client, _ = make_client(scripted(httpx.Response(200))[0])
    assert client.timeout.connect == 10.0
    assert client.timeout.read == 30.0


def test_sends_user_agent_and_params():
    def check(request):
        assert request.headers["user-agent"].startswith("exposure-triage-agent/")
        assert request.url.params["cve"] == "CVE-2021-44228"
        return httpx.Response(200, text="ok")

    client, _ = make_client(scripted(check)[0])
    resp = client.get("https://feeds.example/x", params={"cve": "CVE-2021-44228"})
    assert resp.url.startswith("https://feeds.example/x?")
