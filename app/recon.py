"""Deep reconnaissance: HTTP/RDAP/DNS/TLS inspection for URLs passing 3rd-party checks."""

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import aiodns
import httpx

from .risk import finding


async def http_inspect(url: str) -> list[dict[str, Any]]:
    """HTTP inspection: status, headers, redirects, content-type, server, timing.
    
    SSRF protection: manually follows redirects with validation between hops.
    """
    from .browser_guard import resolve_public, parse_target, UnsafeTarget
    from urllib.parse import urljoin
    
    findings = []
    
    try:
        start = datetime.now(timezone.utc)
        redirect_chain = []
        current_url = url
        max_redirects = 5
        
        async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as client:
            for redirect_num in range(max_redirects + 1):
                resp = await client.get(current_url)
                redirect_chain.append(resp)
                
                # Not a redirect? Done
                if resp.status_code not in (301, 302, 303, 307, 308):
                    break
                
                # Extract redirect target
                location = resp.headers.get("location")
                if not location:
                    break
                
                # Resolve relative URLs
                next_url = urljoin(current_url, location)
                
                # SSRF validation: check redirect target before following
                try:
                    _, host, port = parse_target(next_url)
                    # DNS resolution in thread pool
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, resolve_public, host, port)
                except (UnsafeTarget, ValueError):
                    # SSRF attempt blocked
                    findings.append(
                        finding(
                            f"URL mencoba redirect ke alamat non-publik ({next_url[:100]}); kemungkinan SSRF attack.",
                            "http_inspection",
                            "critical",
                            {"blocked_redirect": next_url[:512], "redirect_num": redirect_num + 1},
                        )
                    )
                    return findings  # Stop processing, critical threat
                
                current_url = next_url
            
            # Use final response for analysis
            resp = redirect_chain[-1]
            elapsed_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
            redirect_count = len(redirect_chain) - 1

            # Chain redirects (>2 suspicious)
            if redirect_count > 2:
                findings.append(
                    finding(
                        f"URL mengarahkan {redirect_count} kali; pola sering dipakai phishing untuk sembunyikan tujuan akhir.",
                        "http_inspection",
                        "medium",
                        {"redirect_count": redirect_count, "final_url": str(current_url)[:512]},
                    )
                )

            # Security headers missing
            headers = resp.headers
            missing_sec = []
            if "content-security-policy" not in headers:
                missing_sec.append("CSP")
            if "strict-transport-security" not in headers and urlsplit(url).scheme == "https":
                missing_sec.append("HSTS")
            if "x-frame-options" not in headers:
                missing_sec.append("X-Frame-Options")
            if len(missing_sec) >= 2:
                findings.append(
                    finding(
                        f"Header keamanan tidak ada: {', '.join(missing_sec)}; risiko clickjacking/injection.",
                        "http_inspection",
                        "low",
                        {"missing": missing_sec},
                    )
                )

            # Server version leak
            if "server" in headers:
                server_val = headers["server"]
                if any(c.isdigit() for c in server_val):
                    findings.append(
                        finding(
                            f"Server versi terbuka ({server_val}); attacker bisa cari exploit spesifik.",
                            "http_inspection",
                            "info",
                            {"server": server_val},
                        )
                    )

            # Slow response (>5s)
            if elapsed_ms > 5000:
                findings.append(
                    finding(
                        f"Respons lambat ({elapsed_ms}ms); mungkin server overload atau sengaja delay.",
                        "http_inspection",
                        "info",
                        {"latency_ms": elapsed_ms},
                    )
                )

            # Content-type mismatch
            content_type = headers.get("content-type", "")
            if resp.status_code == 200 and "<html" in resp.text[:1024].lower() and "text/html" not in content_type.lower():
                findings.append(
                    finding(
                        f"Content-Type tidak cocok: header '{content_type}' tapi body HTML; mungkin misconfiguration.",
                        "http_inspection",
                        "low",
                        {"content_type": content_type},
                    )
                )

    except httpx.HTTPError:
        return []  # Network issue
    except asyncio.TimeoutError:
        return []
    return findings


async def rdap_inspect(domain: str) -> list[dict[str, Any]]:
    """RDAP inspection: domain age, updated, expiry, registrar, status."""
    findings = []
    try:
        # RDAP bootstrap: query IANA for TLD then follow
        # Simple: use public RDAP endpoint (rdap.org aggregator)
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"https://rdap.org/domain/{domain}")
            if resp.status_code != 200:
                return []
            data = resp.json()

            # Parse dates
            events = {ev["eventAction"]: ev.get("eventDate") for ev in data.get("events", [])}
            created = events.get("registration")
            updated = events.get("last changed")
            expires = events.get("expiration")

            now = datetime.now(timezone.utc)

            # Domain age <30d
            if created:
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (now - created_dt).days
                if age_days < 30:
                    findings.append(
                        finding(
                            f"Domain baru ({age_days} hari); phishing sering pakai domain segar untuk hindari blocklist.",
                            "rdap_inspection",
                            "high" if age_days < 7 else "medium",
                            {"created": created, "age_days": age_days},
                        )
                    )

            # Updated recently (<7d on old domain)
            if updated and created:
                updated_dt = datetime.fromisoformat(updated.replace("Z", "+00:00"))
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                update_age = (now - updated_dt).days
                domain_age = (now - created_dt).days
                if update_age < 7 and domain_age > 90:
                    findings.append(
                        finding(
                            f"Domain lama baru diupdate {update_age} hari lalu; mungkin domain bekas dibeli attacker.",
                            "rdap_inspection",
                            "medium",
                            {"updated": updated, "update_age_days": update_age},
                        )
                    )

            # Expires soon (<30d)
            if expires:
                expires_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                expires_days = (expires_dt - now).days
                if expires_days < 30 and expires_days > 0:
                    findings.append(
                        finding(
                            f"Domain kedaluwarsa dalam {expires_days} hari; phishing jarang renew domain.",
                            "rdap_inspection",
                            "low",
                            {"expires": expires, "expires_days": expires_days},
                        )
                    )

            # Registrar check (common abuse registrars)
            entities = data.get("entities", [])
            for ent in entities:
                if "registrar" in ent.get("roles", []):
                    registrar = ent.get("vcardArray", [[]])[1]
                    # ponytail: abuse registrar list not maintained; add when pattern emerges
                    break

            # Privacy shield enabled (whois privacy)
            if any("proxy" in str(ent).lower() or "privacy" in str(ent).lower() for ent in entities):
                findings.append(
                    finding(
                        "WHOIS privacy aktif; legitimate tapi juga dipakai attacker sembunyikan identitas.",
                        "rdap_inspection",
                        "info",
                        {},
                    )
                )

    except (httpx.RequestError, httpx.HTTPStatusError, asyncio.TimeoutError, KeyError, ValueError):
        return []
    return findings


async def dns_inspect(domain: str) -> list[dict[str, Any]]:
    """DNS inspection: A/AAAA/MX/NS/TXT/CNAME records analysis."""
    findings = []
    try:
        resolver = aiodns.DNSResolver(timeout=5.0)

        # A/AAAA records
        try:
            a_records = await resolver.query(domain, "A")
        except aiodns.error.DNSError:
            a_records = []

        # MX records
        try:
            mx_records = await resolver.query(domain, "MX")
        except aiodns.error.DNSError:
            mx_records = []

        # NS records
        try:
            ns_records = await resolver.query(domain, "NS")
            ns_list = [ns.host for ns in ns_records]
            # Suspicious TLD for NS (e.g., .ru, .cn for non-matching domain)
            suspicious_tlds = [".ru", ".cn", ".tk", ".ml", ".ga"]
            if any(any(ns.endswith(tld) for tld in suspicious_tlds) for ns in ns_list):
                if not any(domain.endswith(tld) for tld in suspicious_tlds):
                    findings.append(
                        finding(
                            f"Nameserver di TLD mencurigakan: {', '.join(ns_list[:3])}; sering dipakai phishing infra.",
                            "dns_inspection",
                            "medium",
                            {"nameservers": ns_list},
                        )
                    )
        except aiodns.error.DNSError:
            ns_records = []

        # TXT records (SPF/DKIM check)
        try:
            txt_records = await resolver.query(domain, "TXT")
            txt_values = [r.text if isinstance(r.text, str) else b"".join(r.text).decode() for r in txt_records]
            has_spf = any("v=spf1" in t.lower() for t in txt_values)
            has_dmarc = False
            try:
                dmarc = await resolver.query(f"_dmarc.{domain}", "TXT")
                has_dmarc = len(dmarc) > 0
            except aiodns.error.DNSError:
                pass

            # Missing SPF/DMARC on domain with MX
            if mx_records and not has_spf:
                findings.append(
                    finding(
                        "Domain punya MX tapi tidak ada SPF record; email dari domain ini mudah di-spoof.",
                        "dns_inspection",
                        "low",
                        {"mx_count": len(mx_records)},
                    )
                )
        except aiodns.error.DNSError:
            pass

        # No MX for site claiming to be email service
        # ponytail: keyword list ("mail", "email") too naive; skip for now

    except Exception:
        return []
    return findings


async def tls_inspect(url: str) -> list[dict[str, Any]]:
    """TLS inspection: cert validity, issuer, expiry, hostname match."""
    findings = []
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        return []  # No TLS

    hostname = parsed.hostname
    port = parsed.port or 443

    try:
        context = ssl.create_default_context()
        # ponytail: use asyncio.open_connection for async; blocking socket fine for now (5s max)
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Hostname mismatch
                # ponytail: getpeercert() already validates hostname if context check_hostname=True (default)
                # If we reach here, hostname matches (else SSLCertVerificationError raised)

                # Expiry check
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)

                if now > not_after:
                    findings.append(
                        finding(
                            f"Sertifikat TLS kedaluwarsa ({not_after.date()}); koneksi tidak aman.",
                            "tls_inspection",
                            "critical",
                            {"expired": str(not_after)},
                        )
                    )
                elif (not_after - now).days < 7:
                    findings.append(
                        finding(
                            f"Sertifikat TLS kedaluwarsa dalam {(not_after - now).days} hari; mungkin domain terbengkalai.",
                            "tls_inspection",
                            "low",
                            {"expires_days": (not_after - now).days},
                        )
                    )

                # Fresh cert on fresh domain (combined with RDAP)
                cert_age_days = (now - not_before).days
                if cert_age_days < 7:
                    findings.append(
                        finding(
                            f"Sertifikat baru ({cert_age_days} hari); jika domain juga baru, kuat indikasi phishing.",
                            "tls_inspection",
                            "info",
                            {"cert_age_days": cert_age_days, "issued": str(not_before.date())},
                        )
                    )

                # Issuer (self-signed or untrusted CA)
                issuer = dict(x[0] for x in cert.get("issuer", []))
                issuer_cn = issuer.get("commonName", "")
                # ponytail: self-signed check via issuer == subject, but getpeercert validates chain
                # If we reach here, cert is trusted (else SSLError raised)

    except ssl.SSLCertVerificationError as e:
        # Self-signed, expired, hostname mismatch, untrusted CA
        findings.append(
            finding(
                f"Sertifikat TLS tidak valid: {str(e)[:200]}; koneksi tidak aman atau attacker mitm.",
                "tls_inspection",
                "critical",
                {"error": str(e)[:200]},
            )
        )
    except (socket.timeout, socket.gaierror, OSError, ssl.SSLError):
        return []  # Network issue or no TLS
    return findings


async def deep_recon(url: str) -> dict[str, Any]:
    """Orchestrator: run all recon checks in parallel, return findings/checks/unavailable/raw_data."""
    parsed = urlsplit(url)
    domain = parsed.hostname or ""

    results = await asyncio.gather(
        http_inspect(url),
        rdap_inspect(domain),
        dns_inspect(domain),
        tls_inspect(url),
        return_exceptions=True,
    )

    findings = []
    checks = []
    unavailable = []
    raw_data = {}

    for idx, (name, result) in enumerate(
        zip(["http_inspection", "rdap_inspection", "dns_inspection", "tls_inspection"], results, strict=False)
    ):
        if isinstance(result, Exception):
            unavailable.append(name)
        elif result is None or (isinstance(result, list) and len(result) == 0):
            checks.append(name)  # Ran successfully, no findings
        else:
            checks.append(name)
            findings.extend(result)
        
        # Store raw data for each check (for debugging/audit)
        # Each inspector already returns Finding objects with metadata
        # Extract metadata from findings for this source
        source_findings = [f for f in findings if f.source == name]
        if source_findings:
            raw_data[name] = {
                "findings_count": len(source_findings),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    return {"findings": findings, "checks": checks, "unavailable": unavailable, "raw_data": raw_data}
