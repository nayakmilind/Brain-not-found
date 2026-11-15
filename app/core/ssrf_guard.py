from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

import httpcore
import httpx
from httpcore._backends.auto import AutoBackend
from httpcore._backends.base import AsyncNetworkBackend, AsyncNetworkStream

USER_AGENT = "PrivacyShieldAI/1.0"
_ALLOWED_CONTENT_TYPES = frozenset(
    {
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/xhtml+xml",
        "text/html",
        "text/plain",
    }
)
_BLOCKED_HOSTS = frozenset({"metadata.google.internal", "metadata"})
_BLOCKED_NETWORKS = (
    ipaddress.ip_network("100.100.100.200/32"),
    ipaddress.ip_network("168.63.129.16/32"),
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("fd00:ec2::254/128"),
)
SocketOption = (
    tuple[int, int, int] | tuple[int, int, bytes | bytearray] | tuple[int, int, None, int]
)


class FetchRejected(ValueError):
    """A safe, bounded fetch could not be completed under policy."""


class SSRFRejected(FetchRejected):
    """The URL or its resolved network destination is not safe to fetch."""


class RobotsDisallowed(FetchRejected):
    """The target site's robots.txt disallows this fetch."""


@dataclass(frozen=True)
class Destination:
    host: str
    port: int
    address: ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class FetchResult:
    url: str
    status_code: int
    headers: Mapping[str, str]
    body: bytes


class AddressResolver:
    async def resolve(
        self, host: str, port: int
    ) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            loop = asyncio.get_running_loop()
            try:
                results = await asyncio.wait_for(
                    loop.getaddrinfo(
                        host,
                        port,
                        family=socket.AF_UNSPEC,
                        type=socket.SOCK_STREAM,
                    ),
                    timeout=3,
                )
            except (OSError, TimeoutError) as error:
                raise SSRFRejected("Unable to resolve the URL host") from error
            addresses = tuple(
                dict.fromkeys(ipaddress.ip_address(result[4][0]) for result in results)
            )
            return addresses
        return (literal,)


def parse_http_url(url: str) -> tuple[str, str, int]:
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"} or not parts.netloc:
            raise SSRFRejected("Only absolute HTTP and HTTPS URLs are allowed")
        if parts.username is not None or parts.password is not None:
            raise SSRFRejected("Credentials in source URLs are not allowed")
        host_value = parts.hostname
        if not host_value:
            raise SSRFRejected("The URL must include a host")
        host = host_value.rstrip(".").encode("idna").decode("ascii").lower()
        default_port = 443 if scheme == "https" else 80
        port = parts.port if parts.port is not None else default_port
    except (UnicodeError, ValueError) as error:
        if isinstance(error, SSRFRejected):
            raise
        raise SSRFRejected("The URL is malformed") from error

    if (
        not host
        or host == "localhost"
        or host in _BLOCKED_HOSTS
        or host.endswith((".localhost", ".local", ".internal"))
    ):
        raise SSRFRejected("Local and metadata hosts are not allowed")
    if port != (443 if scheme == "https" else 80):
        raise SSRFRejected("Only the standard HTTP and HTTPS ports are allowed")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        if any(not label or len(label) > 63 for label in host.split(".")):
            raise SSRFRejected("The URL host is malformed") from None
    else:
        if not _is_safe_address(literal):
            raise SSRFRejected("Local and non-public IP addresses are not allowed")
    return scheme, host, port


async def resolve_public_destination(url: str, resolver: AddressResolver) -> Destination:
    scheme, host, port = parse_http_url(url)
    del scheme
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        addresses = await resolver.resolve(host, port)
    else:
        addresses = (literal,)
    if not addresses:
        raise SSRFRejected("The URL host has no usable addresses")
    if any(not _is_safe_address(address) for address in addresses):
        raise SSRFRejected("The URL host resolves to a non-public address")
    return Destination(host=host, port=port, address=addresses[0])


class PinnedNetworkBackend(AsyncNetworkBackend):
    def __init__(
        self,
        destination: Destination,
        backend: AsyncNetworkBackend | None = None,
    ) -> None:
        self._destination = destination
        self._backend = backend or AutoBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 - required by httpcore's protocol
        local_address: str | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> AsyncNetworkStream:
        if host.rstrip(".").lower() != self._destination.host or port != self._destination.port:
            raise SSRFRejected("The HTTP transport attempted an unvalidated destination")
        return await self._backend.connect_tcp(
            str(self._destination.address),
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 - required by httpcore's protocol
        socket_options: Iterable[SocketOption] | None = None,
    ) -> AsyncNetworkStream:
        del path, timeout, socket_options
        raise SSRFRejected("Unix-domain sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


class PinnedHTTPTransport(httpx.AsyncHTTPTransport):
    def __init__(self, destination: Destination) -> None:
        super().__init__(trust_env=False, retries=0)
        pool = self._pool
        if not isinstance(pool, httpcore.AsyncConnectionPool):
            raise RuntimeError("HTTPX is not using the expected HTTP Core connection pool")
        pool._network_backend = PinnedNetworkBackend(destination)


class SafeFetcher:
    def __init__(
        self,
        *,
        resolver: AddressResolver | None = None,
        max_bytes: int = 5_000_000,
        timeout_seconds: float = 8,
        max_redirects: int = 3,
    ) -> None:
        self._resolver = resolver or AddressResolver()
        self._max_bytes = max_bytes
        self._timeout_seconds = timeout_seconds
        self._max_redirects = max_redirects

    async def fetch(self, url: str) -> FetchResult:
        try:
            async with asyncio.timeout(self._timeout_seconds):
                return await self._fetch(url)
        except TimeoutError as error:
            raise FetchRejected("The source fetch timed out") from error

    async def _fetch(self, url: str) -> FetchResult:
        current_url = url
        checked_robots: set[str] = set()
        for redirect_count in range(self._max_redirects + 1):
            destination = await resolve_public_destination(current_url, self._resolver)
            scheme, host, port = parse_http_url(current_url)
            origin = f"{scheme}://{host}:{port}"
            if origin not in checked_robots:
                await self._check_robots(current_url, destination, scheme, host, port)
                checked_robots.add(origin)

            response = await self._request(current_url, destination)
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location:
                    raise FetchRejected("The redirect has no destination")
                if redirect_count >= self._max_redirects:
                    raise FetchRejected("The source exceeded the redirect limit")
                try:
                    next_url = urljoin(current_url, location)
                except ValueError as error:
                    raise FetchRejected("The source returned a malformed redirect") from error
                next_scheme, _, _ = parse_http_url(next_url)
                if scheme == "https" and next_scheme != "https":
                    raise FetchRejected("HTTPS sources cannot redirect to HTTP")
                current_url = next_url
                continue
            if response.status_code < 200 or response.status_code >= 300:
                raise FetchRejected("The source returned an unsuccessful response")
            content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if content_type not in _ALLOWED_CONTENT_TYPES:
                raise FetchRejected("The source content type is not supported")
            return response
        raise FetchRejected("The source exceeded the redirect limit")

    async def _check_robots(
        self,
        target_url: str,
        target: Destination,
        scheme: str,
        host: str,
        port: int,
    ) -> None:
        parts = urlsplit(target_url)
        robots_url = urlunsplit((scheme, parts.netloc, "/robots.txt", "", ""))
        response = await self._request(robots_url, target)
        if response.status_code in {404, 410}:
            return
        if response.status_code < 200 or response.status_code >= 300:
            raise FetchRejected("The site's robots policy could not be verified")
        content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type not in {"text/plain", "text/html", "application/octet-stream"}:
            raise FetchRejected("The site's robots policy has an unsupported content type")
        parser = RobotFileParser()
        parser.set_url(f"{scheme}://{host}:{port}/robots.txt")
        parser.parse(response.body.decode("utf-8", errors="replace").splitlines())
        if not parser.can_fetch(USER_AGENT, target_url):
            raise RobotsDisallowed("The site's robots policy disallows this URL")

    async def _request(self, url: str, destination: Destination) -> FetchResult:
        transport = PinnedHTTPTransport(destination)
        timeout = httpx.Timeout(self._timeout_seconds)
        try:
            async with httpx.AsyncClient(
                transport=transport,
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream(
                    "GET",
                    url,
                    headers={
                        "Accept": (
                            "text/html,application/xhtml+xml,text/plain,"
                            "application/pdf,application/vnd.openxmlformats-officedocument."
                            "wordprocessingml.document"
                        ),
                        "User-Agent": USER_AGENT,
                    },
                ) as response:
                    headers = {key.lower(): value for key, value in response.headers.items()}
                    if response.status_code in {301, 302, 303, 307, 308}:
                        return FetchResult(url, response.status_code, headers, b"")
                    content_length = headers.get("content-length")
                    if content_length is not None:
                        try:
                            if int(content_length) > self._max_bytes:
                                raise FetchRejected("The source exceeds the size limit")
                        except ValueError as error:
                            raise FetchRejected(
                                "The source has an invalid content length"
                            ) from error
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > self._max_bytes:
                            raise FetchRejected("The source exceeds the size limit")
                    return FetchResult(url, response.status_code, headers, bytes(body))
        except httpx.TimeoutException as error:
            raise FetchRejected("The source fetch timed out") from error
        except httpx.RequestError as error:
            raise FetchRejected("The source could not be fetched") from error
        except httpx.InvalidURL as error:
            raise FetchRejected("The source URL is malformed") from error
        except SSRFRejected as error:
            raise FetchRejected("The network destination failed validation") from error


def _is_safe_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return _is_safe_address(address.ipv4_mapped)
    return address.is_global and not any(address in network for network in _BLOCKED_NETWORKS)
