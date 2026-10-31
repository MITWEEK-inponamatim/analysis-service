import asyncio
import ipaddress
import socket
from urllib.parse import SplitResult, urlsplit

NON_PUBLIC_NETWORKS = tuple(map(ipaddress.ip_network, (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "::ffff:0:0/96",
    "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
    "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
)))


class UnsafeTarget(ValueError):
    pass


def parse_target(value: str) -> tuple[SplitResult, str, int]:
    try:
        parsed = urlsplit(value)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeTarget("invalid_url") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise UnsafeTarget("unsupported_target")
    if port not in {80, 443} or (parsed.scheme == "http" and port != 80) or (parsed.scheme == "https" and port != 443):
        raise UnsafeTarget("unsupported_port")
    return parsed, parsed.hostname.rstrip("."), port


def validate_browser_target(value: str) -> tuple[SplitResult, str, int]:
    parsed, host, port = parse_target(value)
    normalized = host.casefold()
    if normalized == "localhost" or normalized.endswith((".localhost", ".local", ".internal")):
        raise UnsafeTarget("local_hostname")
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return parsed, host, port
    if (not address.is_global or address.is_reserved or address.is_multicast or address.is_unspecified
            or address.is_loopback or address.is_link_local or address.is_private
            or any(address.version == network.version and address in network for network in NON_PUBLIC_NETWORKS)):
        raise UnsafeTarget("non_public_address")
    return parsed, host, port


def resolve_public(host: str, port: int) -> list[str]:
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        try:
            records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise UnsafeTarget("dns_resolution_failed") from exc
        addresses = [ipaddress.ip_address(record[4][0].split("%", 1)[0]) for record in records]
    
    # Normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) to IPv4 for validation
    normalized = []
    for addr in addresses:
        if addr.version == 6 and addr.ipv4_mapped:
            # Extract embedded IPv4 from ::ffff:x.x.x.x
            normalized.append(addr.ipv4_mapped)
        else:
            normalized.append(addr)
    
    if not normalized or any(
        not address.is_global or address.is_reserved or address.is_multicast
        or address.is_unspecified or address.is_loopback or address.is_link_local
        or address.is_private or getattr(address, "is_site_local", False)
        or any(address.version == network.version and address in network for network in NON_PUBLIC_NETWORKS)
        for address in normalized
    ):
        raise UnsafeTarget("non_public_address")
    return sorted({str(address) for address in addresses}, key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value).packed))


async def validate_target(value: str) -> str:
    _, host, port = parse_target(value)
    await asyncio.wait_for(asyncio.to_thread(resolve_public, host, port), timeout=3)
    return value
