import asyncio
import ipaddress
from collections.abc import Sequence

import httpx
import pytest

from app.core import ssrf_guard
from app.core.ssrf_guard import (
    AddressResolver,
    Destination,
    FetchRejected,
    FetchResult,
    PinnedHTTPTransport,
    PinnedNetworkBackend,
    RobotsDisallowed,
    SafeFetcher,
    SSRFRejected,
    resolve_public_destination,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/",
        "http://127.0.0.1/",
        "http://10.1.2.3/",
        "http://169.254.169.254/latest/meta-data/",
        "http://168.63.129.16/metadata/",
        "http://100.100.100.200/latest/meta-data/",
        "http://[::1]/",
        "http://[fc00::1]/",
        "http://[::ffff:168.63.129.16]/",
        "http://metadata.google.internal/",
        "http://printer.local/",
        "http://localhost/",
        "http://user:password@example.com/",
        "http://example.com:8080/",
        "http://example.com:0/",
    ],
)
async def test_rejects_unsafe_url_forms(url: str) -> None:
    with pytest.raises(SSRFRejected):
        await resolve_public_destination(url, StaticResolver(["93.184.216.34"]))


class StaticResolver(AddressResolver):
    def __init__(self, addresses: Sequence[str]) -> None:
        self.addresses = tuple(ipaddress.ip_address(address) for address in addresses)
        self.hosts: list[str] = []

    async def resolve(
        self, host: str, port: int
    ) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
        self.hosts.append(host)
        return self.addresses


class ChangingResolver(AddressResolver):
    def __init__(self) -> None:
        self.calls = 0

    async def resolve(
        self, host: str, port: int
    ) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
        assert host == "example.com"
        assert port == 443
        self.calls += 1
        address = "93.184.216.34" if self.calls == 1 else "127.0.0.1"
        return (ipaddress.ip_address(address),)


@pytest.mark.asyncio
async def test_rejects_dns_answers_containing_any_non_global_ip() -> None:
    resolver = StaticResolver(["93.184.216.34", "168.63.129.16"])

    with pytest.raises(SSRFRejected, match="non-public"):
        await resolve_public_destination("https://example.com/", resolver)


@pytest.mark.asyncio
async def test_pins_a_public_dns_answer() -> None:
    resolver = StaticResolver(["93.184.216.34", "1.1.1.1"])

    destination = await resolve_public_destination("https://example.com/", resolver)

    assert destination == Destination(
        host="example.com",
        port=443,
        address=ipaddress.ip_address("93.184.216.34"),
    )


@pytest.mark.asyncio
async def test_system_resolver_deduplicates_results(monkeypatch: pytest.MonkeyPatch) -> None:
    loop = asyncio.get_running_loop()

    async def getaddrinfo(
        host: str,
        port: int,
        *,
        family: int,
        type: int,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        assert host == "example.com"
        assert port == 443
        assert family == 0
        assert type != 0
        return [
            (2, 1, 6, "", ("93.184.216.34", port)),
            (2, 1, 6, "", ("93.184.216.34", port)),
            (2, 1, 6, "", ("1.1.1.1", port)),
        ]

    monkeypatch.setattr(loop, "getaddrinfo", getaddrinfo)
    addresses = await AddressResolver().resolve("example.com", 443)
    assert addresses == (
        ipaddress.ip_address("93.184.216.34"),
        ipaddress.ip_address("1.1.1.1"),
    )


@pytest.mark.asyncio
async def test_system_resolver_errors_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    loop = asyncio.get_running_loop()

    async def fail_getaddrinfo(*_args: object, **_kwargs: object) -> list[object]:
        raise OSError("synthetic resolver error")

    monkeypatch.setattr(loop, "getaddrinfo", fail_getaddrinfo)
    with pytest.raises(SSRFRejected, match="resolve"):
        await AddressResolver().resolve("unresolvable.example", 443)


@pytest.mark.asyncio
async def test_pinned_backend_connects_to_the_selected_ip_only() -> None:
    class RecordingBackend:
        def __init__(self) -> None:
            self.destinations: list[tuple[str, int]] = []
            self.slept = False

        async def connect_tcp(
            self,
            host: str,
            port: int,
            **_kwargs: object,
        ) -> object:
            self.destinations.append((host, port))
            raise OSError("stop before opening a socket")

        async def connect_unix_socket(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("Unix sockets must never be attempted")

        async def sleep(self, _seconds: float) -> None:
            self.slept = True

    backend = RecordingBackend()
    destination = Destination(
        "example.com",
        443,
        ipaddress.ip_address("93.184.216.34"),
    )
    pinned = PinnedNetworkBackend(destination, backend)  # type: ignore[arg-type]
    with pytest.raises(OSError, match="stop"):
        await pinned.connect_tcp("example.com", 443)
    assert backend.destinations == [("93.184.216.34", 443)]
    with pytest.raises(SSRFRejected):
        await pinned.connect_tcp("attacker.example", 443)
    with pytest.raises(SSRFRejected):
        await pinned.connect_unix_socket("/tmp/socket")
    await pinned.sleep(0)
    assert backend.slept


class MockAsyncTransport(httpx.AsyncBaseTransport):
    def __init__(self, handler: object) -> None:
        self._handler = handler

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._handler(request)  # type: ignore[operator]


class ByteChunks(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def __aiter__(self):
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        return None


def _mock_fetcher(
    monkeypatch: pytest.MonkeyPatch,
    resolver: AddressResolver,
    handler: object,
    *,
    max_bytes: int = 1024,
    max_redirects: int = 3,
    timeout_seconds: float = 1,
) -> SafeFetcher:
    monkeypatch.setattr(
        ssrf_guard,
        "PinnedHTTPTransport",
        lambda _destination: MockAsyncTransport(handler),
    )
    return SafeFetcher(
        resolver=resolver,
        max_bytes=max_bytes,
        timeout_seconds=timeout_seconds,
        max_redirects=max_redirects,
    )


@pytest.mark.asyncio
async def test_fetch_respects_robots_and_content_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        if request.url.path == "/robots.txt":
            return httpx.Response(404, request=request)
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            content=b"synthetic page",
            request=request,
        )

    fetcher = _mock_fetcher(
        monkeypatch,
        StaticResolver(["93.184.216.34"]),
        handler,
    )
    result = await fetcher.fetch("https://example.com/profile")
    assert result.body == b"synthetic page"
    assert requests == ["/robots.txt", "/profile"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content_type",
    [
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ],
)
async def test_fetch_accepts_supported_document_downloads(
    monkeypatch: pytest.MonkeyPatch,
    content_type: str,
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404, request=request)
        assert "application/pdf" in request.headers["accept"]
        return httpx.Response(
            200,
            headers={"content-type": content_type},
            content=b"synthetic document",
            request=request,
        )

    fetcher = _mock_fetcher(
        monkeypatch,
        StaticResolver(["93.184.216.34"]),
        handler,
    )

    result = await fetcher.fetch("https://example.com/document")

    assert result.body == b"synthetic document"
    assert result.headers["content-type"] == content_type


@pytest.mark.asyncio
async def test_fetch_blocks_robots_disallow_and_robots_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def disallow(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            content=b"User-agent: *\nDisallow: /private",
            request=request,
        )

    fetcher = _mock_fetcher(
        monkeypatch,
        StaticResolver(["93.184.216.34"]),
        disallow,
    )
    with pytest.raises(RobotsDisallowed):
        await fetcher.fetch("https://example.com/private")

    async def redirect_robots(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"location": "https://example.com/robots-v2.txt"},
            request=request,
        )

    fetcher = _mock_fetcher(
        monkeypatch,
        StaticResolver(["93.184.216.34"]),
        redirect_robots,
    )
    with pytest.raises(FetchRejected, match="robots policy"):
        await fetcher.fetch("https://example.com/profile")


@pytest.mark.asyncio
async def test_fetch_limits_size_type_status_and_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def too_large(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404, request=request)
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            stream=ByteChunks([b"01234", b"56789", b"0"]),
            request=request,
        )

    fetcher = _mock_fetcher(
        monkeypatch,
        StaticResolver(["93.184.216.34"]),
        too_large,
        max_bytes=10,
    )
    with pytest.raises(FetchRejected, match="size limit"):
        await fetcher.fetch("https://example.com/large")

    async def unsupported(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404, request=request)
        return httpx.Response(
            200,
            headers={"content-type": "image/svg+xml"},
            content=b"<svg/>",
            request=request,
        )

    fetcher = _mock_fetcher(
        monkeypatch,
        StaticResolver(["93.184.216.34"]),
        unsupported,
    )
    with pytest.raises(FetchRejected, match="content type"):
        await fetcher.fetch("https://example.com/file")

    async def failed(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404, request=request)
        return httpx.Response(500, request=request)

    fetcher = _mock_fetcher(
        monkeypatch,
        StaticResolver(["93.184.216.34"]),
        failed,
    )
    with pytest.raises(FetchRejected, match="unsuccessful"):
        await fetcher.fetch("https://example.com/error")

    async def redirects(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404, request=request)
        return httpx.Response(
            302,
            headers={"location": "/next"},
            request=request,
        )

    fetcher = _mock_fetcher(
        monkeypatch,
        StaticResolver(["93.184.216.34"]),
        redirects,
        max_redirects=1,
    )
    with pytest.raises(FetchRejected, match="redirect limit"):
        await fetcher.fetch("https://example.com/start")


@pytest.mark.asyncio
async def test_fetch_rejects_redirects_to_private_addresses_and_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def private_redirect(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404, request=request)
        return httpx.Response(
            302,
            headers={"location": "http://127.0.0.1/admin"},
            request=request,
        )

    fetcher = _mock_fetcher(
        monkeypatch,
        StaticResolver(["93.184.216.34"]),
        private_redirect,
    )
    with pytest.raises(SSRFRejected):
        await fetcher.fetch("https://example.com/redirect")

    async def timeout(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404, request=request)
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    fetcher = _mock_fetcher(
        monkeypatch,
        StaticResolver(["93.184.216.34"]),
        timeout,
    )
    with pytest.raises(FetchRejected, match="timed out"):
        await fetcher.fetch("https://example.com/slow")


@pytest.mark.asyncio
async def test_fetch_applies_one_deadline_to_the_complete_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def slow_robots(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.05)
        return httpx.Response(404, request=request)

    fetcher = _mock_fetcher(
        monkeypatch,
        StaticResolver(["93.184.216.34"]),
        slow_robots,
        timeout_seconds=0.01,
    )
    with pytest.raises(FetchRejected, match="timed out"):
        await fetcher.fetch("https://example.com/slow")


def test_pinned_transport_installs_its_network_backend() -> None:
    transport = PinnedHTTPTransport(
        Destination("example.com", 443, ipaddress.ip_address("93.184.216.34"))
    )
    try:
        assert isinstance(transport._pool._network_backend, PinnedNetworkBackend)
    finally:
        import asyncio

        asyncio.run(transport.aclose())


class ScriptedFetcher(SafeFetcher):
    def __init__(self, resolver: AddressResolver, responses: list[FetchResult]) -> None:
        super().__init__(resolver=resolver, max_redirects=2)
        self.responses = iter(responses)
        self.requests: list[tuple[str, Destination]] = []
        self.robots_checks: list[str] = []

    async def _check_robots(
        self,
        target_url: str,
        target: Destination,
        scheme: str,
        host: str,
        port: int,
    ) -> None:
        self.robots_checks.append(f"{scheme}://{host}:{port}")

    async def _request(self, url: str, destination: Destination) -> FetchResult:
        self.requests.append((url, destination))
        return next(self.responses)


@pytest.mark.asyncio
async def test_revalidates_and_repins_every_redirect() -> None:
    resolver = StaticResolver(["93.184.216.34"])
    fetcher = ScriptedFetcher(
        resolver,
        [
            FetchResult(
                "https://example.com/start",
                302,
                {"location": "https://cdn.example.net/page"},
                b"",
            ),
            FetchResult(
                "https://cdn.example.net/page",
                200,
                {"content-type": "text/html"},
                b"ok",
            ),
        ],
    )

    result = await fetcher.fetch("https://example.com/start")

    assert result.body == b"ok"
    assert resolver.hosts == ["example.com", "cdn.example.net"]
    assert [origin for origin in fetcher.robots_checks] == [
        "https://example.com:443",
        "https://cdn.example.net:443",
    ]
    assert [destination.host for _, destination in fetcher.requests] == [
        "example.com",
        "cdn.example.net",
    ]


@pytest.mark.asyncio
async def test_rejects_dns_rebinding_between_redirects() -> None:
    resolver = ChangingResolver()
    fetcher = ScriptedFetcher(
        resolver,
        [
            FetchResult(
                "https://example.com/start",
                302,
                {"location": "https://example.com/next"},
                b"",
            ),
        ],
    )
    with pytest.raises(SSRFRejected, match="non-public"):
        await fetcher.fetch("https://example.com/start")
    assert resolver.calls == 2
    assert len(fetcher.requests) == 1


@pytest.mark.asyncio
async def test_rejects_https_downgrade_redirect() -> None:
    fetcher = ScriptedFetcher(
        StaticResolver(["93.184.216.34"]),
        [
            FetchResult(
                "https://example.com/start",
                302,
                {"location": "http://example.com/insecure"},
                b"",
            )
        ],
    )

    with pytest.raises(FetchRejected, match="HTTPS sources"):
        await fetcher.fetch("https://example.com/start")
