#!/usr/bin/env python3
"""Apply production-hardening fixes to the ThreatMap repository.

Run from the repository root:
    python apply_threatmap_fixes.py .

The script creates a timestamped backup before modifying files. It is designed
for the current public ThreatMap repository layout and safely tolerates sections
that have already been fixed, removed, or reformatted.
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import shutil
import sys
from pathlib import Path

PATCH_MARKER = "ThreatMap production hardening patch"

VALIDATORS_PY = r'''"""Strict IOC and outbound URL validation.

ThreatMap production hardening patch.
"""
from __future__ import annotations

import asyncio
import re
import socket
from ipaddress import ip_address
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from fastapi import HTTPException, status

_DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)


def _bad_request(message: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)


def validate_public_ip(value: str) -> str:
    """Return a canonical, globally routable IPv4/IPv6 address."""
    raw = (value or "").strip()
    if not raw:
        raise _bad_request("IP address is required.")
    try:
        address = ip_address(raw)
    except ValueError as exc:
        raise _bad_request("Invalid IPv4 or IPv6 address.") from exc

    # Public threat-intelligence providers do not meaningfully analyse local,
    # loopback, multicast, link-local or reserved targets. Rejecting them also
    # reduces SSRF and internal-network disclosure risk on a public deployment.
    if not address.is_global:
        raise _bad_request("Only publicly routable IP addresses can be scanned.")
    return str(address)


def validate_domain(value: str) -> str:
    """Validate and return a canonical ASCII/IDNA public domain name."""
    raw = (value or "").strip().lower().rstrip(".")
    if not raw:
        raise _bad_request("Domain is required.")
    if any(token in raw for token in ("://", "/", "\\", "@", "?", "#")):
        raise _bad_request("Enter a domain only, without a URL path or scheme.")

    try:
        # Reject IP literals submitted through the domain route.
        ip_address(raw)
    except ValueError:
        pass
    else:
        raise _bad_request("Use the IP scanner for IP addresses.")

    try:
        ascii_domain = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise _bad_request("Invalid internationalised domain name.") from exc

    if len(ascii_domain) > 253 or "." not in ascii_domain:
        raise _bad_request("Enter a valid public domain name.")

    labels = ascii_domain.split(".")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise _bad_request("Enter a valid public domain name.")
    return ascii_domain


def validate_url(value: str) -> str:
    """Validate an HTTP(S) URL before any outbound request is attempted."""
    raw = (value or "").strip()
    if not raw:
        raise _bad_request("URL is required.")
    if len(raw) > 2048:
        raise _bad_request("URL is too long.")

    try:
        parsed = urlsplit(raw)
        _ = parsed.port  # Triggers validation of malformed ports.
    except ValueError as exc:
        raise _bad_request("Invalid URL.") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise _bad_request("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname:
        raise _bad_request("URL must contain a valid hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise _bad_request("URLs containing embedded credentials are not allowed.")

    hostname = parsed.hostname.rstrip(".").lower()
    try:
        ip_address(hostname)
    except ValueError:
        validate_domain(hostname)
    else:
        validate_public_ip(hostname)
    return raw


async def ensure_public_url_target(url: str) -> None:
    """Resolve a URL hostname and reject non-public destinations."""
    parsed = urlsplit(validate_url(url))
    hostname = parsed.hostname
    if not hostname:
        raise _bad_request("URL must contain a hostname.")

    try:
        validate_public_ip(hostname)
        return
    except HTTPException:
        # It may be a domain rather than an IP literal.
        try:
            ip_address(hostname)
        except ValueError:
            pass
        else:
            raise

    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    loop = asyncio.get_running_loop()

    def _resolve() -> list[tuple[Any, ...]]:
        return socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)

    try:
        records = await loop.run_in_executor(None, _resolve)
    except socket.gaierror as exc:
        raise _bad_request("The URL hostname could not be resolved.") from exc

    resolved = {record[4][0] for record in records if record and record[4]}
    if not resolved:
        raise _bad_request("The URL hostname could not be resolved.")
    for resolved_ip in resolved:
        validate_public_ip(resolved_ip)


async def fetch_public_url_text(
    url: str,
    *,
    max_redirects: int = 3,
    max_bytes: int = 1_000_000,
) -> dict[str, Any]:
    """Safely fetch a bounded amount of text from a validated public URL.

    Redirect destinations are revalidated. TLS certificate verification remains
    enabled. The response body is capped to limit memory consumption.
    """
    current = validate_url(url)
    timeout = httpx.Timeout(7.0, connect=4.0)
    limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
    headers = {"User-Agent": "ThreatMap-SafeFetcher/1.0"}

    async with httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        follow_redirects=False,
        verify=True,
        headers=headers,
    ) as client:
        for redirect_count in range(max_redirects + 1):
            await ensure_public_url_target(current)
            async with client.stream("GET", current) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location:
                        break
                    if redirect_count >= max_redirects:
                        raise _bad_request("URL redirected too many times.")
                    current = validate_url(urljoin(current, location))
                    continue

                data = bytearray()
                async for chunk in response.aiter_bytes():
                    remaining = max_bytes - len(data)
                    if remaining <= 0:
                        break
                    data.extend(chunk[:remaining])
                    if len(data) >= max_bytes:
                        break

                encoding = response.encoding or "utf-8"
                text = bytes(data).decode(encoding, errors="replace")
                return {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "text": text,
                    "url": str(response.url),
                }

    raise _bad_request("Unable to retrieve the URL safely.")
'''

VALIDATOR_TESTS = r'''from fastapi import HTTPException
import pytest

from core.validators import validate_domain, validate_public_ip, validate_url


def test_public_ip_is_accepted():
    assert validate_public_ip("8.8.8.8") == "8.8.8.8"


@pytest.mark.parametrize("value", ["999.999.999.999", "hello", "127.0.0.1", "10.0.0.1"])
def test_invalid_or_private_ip_is_rejected(value):
    with pytest.raises(HTTPException):
        validate_public_ip(value)


def test_public_domain_is_accepted():
    assert validate_domain("GitHub.COM.") == "github.com"


@pytest.mark.parametrize("value", ["not a domain", "localhost", "https://github.com/path", "127.0.0.1"])
def test_invalid_domain_is_rejected(value):
    with pytest.raises(HTTPException):
        validate_domain(value)


def test_https_url_is_accepted():
    assert validate_url("https://github.com/") == "https://github.com/"


@pytest.mark.parametrize("value", ["file:///etc/passwd", "http://localhost/", "http://127.0.0.1/", "ftp://github.com/"])
def test_unsafe_url_is_rejected(value):
    with pytest.raises(HTTPException):
        validate_url(value)
'''

BULK_PAGE_TSX = r'''"use client";

// ThreatMap production hardening patch
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

type AnyRecord = Record<string, any>;

function normaliseResults(payload: AnyRecord | AnyRecord[] | null): AnyRecord[] {
  if (!payload) return [];
  if (Array.isArray(payload)) return payload;
  const candidate = payload.results ?? payload.items ?? payload.data ?? payload.scans;
  return Array.isArray(candidate) ? candidate : [];
}

function text(value: unknown, fallback = "—") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

export default function BulkResultsPage() {
  const [payload, setPayload] = useState<AnyRecord | AnyRecord[] | null>(null);
  const [loadError, setLoadError] = useState("");

  useEffect(() => {
    try {
      const raw = sessionStorage.getItem("bulkScanResults");
      if (!raw) {
        setLoadError("No bulk scan data was found. Start a new bulk scan from the scanner.");
        return;
      }
      setPayload(JSON.parse(raw));
    } catch {
      setLoadError("The saved bulk result could not be read. Start a new bulk scan.");
    }
  }, []);

  const results = useMemo(() => normaliseResults(payload), [payload]);

  const downloadJson = () => {
    if (!payload) return;
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = `threatmap-bulk-results-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(href);
  };

  if (loadError) {
    return (
      <main className="min-h-screen bg-[#050b14] text-white flex items-center justify-center p-6">
        <section className="w-full max-w-xl rounded-2xl border border-white/10 bg-white/5 p-8 text-center">
          <h1 className="text-2xl font-semibold">Bulk results unavailable</h1>
          <p className="mt-3 text-sm text-slate-400">{loadError}</p>
          <Link
            href="/"
            className="mt-6 inline-flex rounded-lg bg-cyan-400 px-5 py-3 font-semibold text-slate-950"
          >
            Return to scanner
          </Link>
        </section>
      </main>
    );
  }

  if (!payload) {
    return (
      <main className="min-h-screen bg-[#050b14] text-white flex items-center justify-center">
        <p className="text-slate-400">Loading bulk results…</p>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-[#050b14] text-white p-6 md:p-10">
      <div className="mx-auto max-w-7xl">
        <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-cyan-300">ThreatMap</p>
            <h1 className="mt-2 text-3xl font-semibold">Bulk scan results</h1>
            <p className="mt-2 text-sm text-slate-400">{results.length} indicator result(s)</p>
          </div>
          <div className="flex gap-3">
            <button
              onClick={downloadJson}
              className="rounded-lg border border-white/15 px-4 py-2 text-sm hover:bg-white/5"
            >
              Download JSON
            </button>
            <Link href="/" className="rounded-lg bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950">
              New scan
            </Link>
          </div>
        </div>

        {results.length === 0 ? (
          <section className="rounded-2xl border border-amber-300/20 bg-amber-300/5 p-6">
            <h2 className="font-semibold text-amber-200">No item-level results returned</h2>
            <p className="mt-2 text-sm text-slate-400">
              The backend response was saved, but it did not contain a recognised results array. Download the JSON for diagnostics.
            </p>
          </section>
        ) : (
          <div className="overflow-x-auto rounded-2xl border border-white/10 bg-white/[0.03]">
            <table className="w-full min-w-[780px] text-left text-sm">
              <thead className="border-b border-white/10 text-xs uppercase tracking-wider text-slate-400">
                <tr>
                  <th className="px-5 py-4">Indicator</th>
                  <th className="px-5 py-4">Type</th>
                  <th className="px-5 py-4">Risk score</th>
                  <th className="px-5 py-4">Risk level</th>
                  <th className="px-5 py-4">Status</th>
                </tr>
              </thead>
              <tbody>
                {results.map((item, index) => {
                  const indicator = item.indicator ?? item.value ?? item.ioc ?? item.target;
                  const score = item.risk_score ?? item.score ?? item.riskScore;
                  const level = item.risk_level ?? item.severity ?? item.riskLevel;
                  const status = item.error ? `Error: ${item.error}` : item.status ?? "Completed";
                  return (
                    <tr key={`${text(indicator, "item")}-${index}`} className="border-b border-white/5 last:border-0">
                      <td className="max-w-md break-all px-5 py-4 font-mono text-cyan-200">{text(indicator)}</td>
                      <td className="px-5 py-4 text-slate-300">{text(item.type ?? item.ioc_type)}</td>
                      <td className="px-5 py-4">{text(score)}</td>
                      <td className="px-5 py-4">{text(level)}</td>
                      <td className="max-w-sm break-words px-5 py-4 text-slate-300">{text(status)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </main>
  );
}
'''


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", nargs="?", default=".", help="ThreatMap repository root")
    parser.add_argument("--dry-run", action="store_true", help="Validate expected files without writing")
    parser.add_argument("--force", action="store_true", help="Overwrite patch-created files when they differ")
    return parser.parse_args()


class Patcher:
    def __init__(self, root: Path, dry_run: bool, force: bool) -> None:
        self.root = root.resolve()
        self.dry_run = dry_run
        self.force = force
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.backup_root = self.root / f".threatmap-backup-{stamp}"
        self.changed: list[Path] = []
        self.messages: list[str] = []

    def path(self, relative: str) -> Path:
        return self.root / relative

    def require_layout(self) -> None:
        required = ["backend/main.py", "frontend/app/page.tsx", "backend/routers/ip.py", "backend/routers/domain.py", "backend/routers/url.py"]
        missing = [item for item in required if not self.path(item).is_file()]
        if missing:
            raise RuntimeError("Not a compatible ThreatMap repository. Missing: " + ", ".join(missing))

    def _backup(self, path: Path) -> None:
        if self.dry_run or path in self.changed or not path.exists():
            return
        destination = self.backup_root / path.relative_to(self.root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)

    def write(self, relative: str, content: str) -> None:
        path = self.path(relative)
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == content:
            self.messages.append(f"SKIP {relative} (already current)")
            return
        if current is not None and PATCH_MARKER in current and not self.force:
            raise RuntimeError(f"{relative} already contains a different patch version; rerun with --force after reviewing it.")
        if self.dry_run:
            self.messages.append(f"WOULD WRITE {relative}")
            return
        self._backup(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
        self.changed.append(path)
        self.messages.append(f"WRITE {relative}")

    def transform(self, relative: str, transform_fn) -> None:
        path = self.path(relative)
        original = path.read_text(encoding="utf-8")
        updated = transform_fn(original)
        if updated == original:
            self.messages.append(f"SKIP {relative} (no changes needed)")
            return
        if self.dry_run:
            self.messages.append(f"WOULD PATCH {relative}")
            return
        self._backup(path)
        path.write_text(updated, encoding="utf-8", newline="\n")
        self.changed.append(path)
        self.messages.append(f"PATCH {relative}")


def replace_once(text: str, old: str, new: str, label: str, *, already: str | None = None) -> str:
    if already and already in text:
        return text
    if old in text:
        return text.replace(old, new, 1)
    raise RuntimeError(f"Could not locate expected source block: {label}")


def regex_once(text: str, pattern: str, replacement: str, label: str, *, already: str | None = None, flags: int = 0) -> str:
    if already and already in text:
        return text
    updated, count = re.subn(pattern, replacement, text, count=1, flags=flags)
    if count != 1:
        raise RuntimeError(f"Could not locate expected source block: {label}")
    return updated


def normalize_health_routes(source: str) -> str:
    """Replace zero, one, or many health handlers with one canonical handler.

    This uses line structure instead of an exact source block, so it remains
    safe when a route was already removed, reformatted, or changed.
    """
    lines = source.splitlines(keepends=True)
    route_ranges: list[tuple[int, int]] = []

    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        is_health_decorator = (
            stripped.startswith("@app.get(")
            and "settings.API_V1_STR" in stripped
            and "/health" in stripped
        )
        if not is_health_decorator:
            index += 1
            continue

        start = index
        previous = start - 1
        while previous >= 0 and not lines[previous].strip():
            previous -= 1
        if previous >= 0 and "health check" in lines[previous].strip().lower():
            start = previous

        def_index = index + 1
        while def_index < len(lines) and not lines[def_index].strip():
            def_index += 1
        if def_index >= len(lines) or not re.match(
            r"^(?:async\s+)?def\s+health_check\s*\(", lines[def_index].lstrip()
        ):
            index += 1
            continue

        end = def_index + 1
        while end < len(lines):
            line = lines[end]
            if not line.strip():
                end += 1
                continue
            if line.startswith((" ", "\t")):
                end += 1
                continue
            break
        route_ranges.append((start, end))
        index = end

    for start, end in reversed(route_ranges):
        del lines[start:end]

    canonical = (
        '# Health Check\n'
        '@app.get(f"{settings.API_V1_STR}/health", tags=["System"])\n'
        'async def health_check():\n'
        '    return {\n'
        '        "status": "ok",\n'
        '        "service": "ThreatMap API",\n'
        '        "version": settings.VERSION,\n'
        '    }\n\n'
    )

    insert_at = None
    for i, line in enumerate(lines):
        if line.lstrip().startswith("# Include Routers"):
            insert_at = i
            break
    if insert_at is None:
        for i, line in enumerate(lines):
            if line.startswith("if ip:") or "app.include_router(ip.router" in line:
                insert_at = i
                break
    if insert_at is None:
        insert_at = len(lines)

    while insert_at > 0 and not lines[insert_at - 1].strip():
        del lines[insert_at - 1]
        insert_at -= 1
    lines.insert(insert_at, "\n" + canonical)
    return "".join(lines)


def dedupe_alert_router(source: str) -> str:
    """Keep exactly one guarded, API-prefixed alert router registration."""
    lines = source.splitlines(keepends=True)
    output: list[str] = []
    i = 0
    inserted = False

    while i < len(lines):
        stripped = lines[i].strip()
        if stripped == "if alert_router:":
            j = i + 1
            block: list[str] = []
            while j < len(lines):
                candidate = lines[j]
                if not candidate.strip():
                    block.append(candidate)
                    j += 1
                    continue
                if candidate.startswith((" ", "\t")):
                    block.append(candidate)
                    j += 1
                    continue
                break

            if any("app.include_router(alert_router" in item for item in block):
                if not inserted:
                    output.append("if alert_router:\n")
                    output.append("    app.include_router(alert_router, prefix=settings.API_V1_STR)\n")
                    inserted = True
                i = j
                continue

        if stripped.startswith("app.include_router(alert_router"):
            if not inserted:
                output.append("if alert_router:\n")
                output.append("    app.include_router(alert_router, prefix=settings.API_V1_STR)\n")
                inserted = True
            i += 1
            continue

        output.append(lines[i])
        i += 1

    return "".join(output)


def patch_main(source: str) -> str:
    source = normalize_health_routes(source)
    source = dedupe_alert_router(source)

    source = re.sub(
        r"\n[ \t]*if scans_count == 0 and total_all_scans > 0:\n[ \t]+scans_count = total_all_scans\n",
        "\n",
        source,
        count=1,
    )

    source = source.replace(
        'content={"error": str(exc), "detail": "Internal server error - check backend logs."}',
        'content={"detail": "Internal server error."}',
        1,
    )

    telemetry_replacement = '''@app.get(f"{settings.API_V1_STR}/dashboard/telemetry", tags=["Telemetry"])
async def get_dashboard_telemetry(db: Session = Depends(get_db)):
    """Return real telemetry only; never substitute demonstration figures."""
    total_scans = db.query(Scan).count()
    high_risk_count = db.query(Scan).filter(Scan.risk_score >= 70).count()

    try:
        health = await get_api_health()
        active_apis = sum(
            1 for item in health.get("apis", [])
            if str(item.get("status", "")).lower() == "online"
        )
    except Exception:
        logger.exception("Unable to calculate active API count")
        active_apis = 0

    return {
        "total_scans": total_scans,
        "high_risk_count": high_risk_count,
        "active_apis": active_apis,
        "avg_scan_time": "N/A",
    }
'''
    if '"""Return real telemetry only; never substitute demonstration figures."""' not in source:
        source, _ = re.subn(
            r'@app\.get\(f"\{settings\.API_V1_STR\}/dashboard/telemetry", tags=\["Telemetry"\]\)\n(?:async\s+)?def get_dashboard_telemetry\(db: Session = Depends\(get_db\)\):\n.*?(?=\n# Vercel requires|\nif __name__ == "__main__"|\Z)',
            telemetry_replacement.rstrip(),
            source,
            count=1,
            flags=re.S,
        )
    return source

def insert_import(source: str, anchor: str, import_line: str, label: str) -> str:
    if import_line in source:
        return source
    if anchor in source:
        return source.replace(anchor, anchor + "\n" + import_line, 1)

    # Fallback for locally reordered imports: insert before the first model or
    # service import instead of aborting the complete fix operation.
    match = re.search(r"^(?:from models|from services|import logging)\b", source, flags=re.M)
    if match:
        return source[:match.start()] + import_line + "\n" + source[match.start():]
    return import_line + "\n" + source


def replace_indicator_validation(source: str, variable: str, validator: str) -> str:
    if f"{variable} = {validator}(payload.indicator)" in source:
        return source

    pattern = rf'''(?mx)
        ^(?P<indent>[ \t]+){re.escape(variable)}[ \t]*=[ \t]*payload\.indicator\.strip\(\)[ \t]*\n
        (?:(?P=indent)\#[^\n]*\n)?
        (?P=indent)if[ \t]+not[ \t]+{re.escape(variable)}:[ \t]*\n
        (?P=indent)[ \t]+raise[ \t]+HTTPException\([^\n]*\)[ \t]*
    '''

    def replacement(match: re.Match[str]) -> str:
        indent = match.group("indent")
        return f"{indent}{variable} = {validator}(payload.indicator)"

    updated, _ = re.subn(pattern, replacement, source, count=1)
    return updated


def patch_ip(source: str) -> str:
    source = insert_import(source, "from core.cache import cache_service", "from core.validators import validate_public_ip", "IP validator")
    source = replace_indicator_validation(source, "ip", "validate_public_ip")

    # Do not return internal provider errors to the public client.
    source = re.sub(
        r'detail=f"Failed gathering threat vectors: \{str\(e\)\}"',
        'detail="Failed gathering threat vectors."',
        source,
        count=1,
    )
    source = re.sub(
        r'detail=f"Scan failed: \{str\(e\)\}"',
        'detail="IP analysis failed."',
        source,
        count=1,
    )
    return source


def patch_domain(source: str) -> str:
    source = insert_import(source, "from core.cache import cache_service", "from core.validators import validate_domain", "domain validator")
    source = replace_indicator_validation(source, "domain", "validate_domain")
    source = source.replace(
        'return {"error": str(e), "risk_score": 0, "risk_level": "UNKNOWN"}',
        'raise HTTPException(status_code=500, detail="Domain analysis failed.")',
        1,
    )
    return source


def patch_url(source: str) -> str:
    source = insert_import(source, "from core.cache import cache_service", "from core.validators import fetch_public_url_text, validate_url", "URL validator")
    source = replace_indicator_validation(source, "target_url", "validate_url")

    safer_fetch = '''        # Phishing Kit Fingerprinting (bounded fetch, TLS verification and SSRF protection)
        phishing_kit_matches = []
        try:
            fetched = await fetch_public_url_text(target_url)
            body = fetched["text"].lower()
            headers = {k.lower(): v.lower() for k, v in fetched["headers"].items()}
            final_url = fetched["url"].lower()

            if "x-mailer" in headers and "phish" in headers["x-mailer"]:
                phishing_kit_matches.append("Generic Phishing Mailer")
            if "paypal" in body and "login" in body and "paypal.com" not in final_url:
                phishing_kit_matches.append("PayPal Credential Harvester")
            if "microsoft" in body and "sign in" in body and "microsoft.com" not in final_url:
                phishing_kit_matches.append("Microsoft 365 Phishing Kit")
            if 'name="generator"' in body and "mura cms" in body:
                phishing_kit_matches.append("Mura CMS (Potentially Compromised)")
        except HTTPException:
            raise
        except Exception:
            logger.exception("Safe URL fingerprinting failed")
        raw_aggregation["phishing_kit_matches"] = phishing_kit_matches'''

    if "bounded fetch, TLS verification and SSRF protection" not in source:
        source, _ = re.subn(
            r'(?ms)^[ \t]+# Phishing Kit Fingerprinting.*?^[ \t]+raw_aggregation\["phishing_kit_matches"\] = phishing_kit_matches',
            safer_fetch,
            source,
            count=1,
        )

    source = source.replace(
        'return {"error": str(e), "risk_score": 0, "risk_level": "UNKNOWN"}',
        'raise HTTPException(status_code=500, detail="URL analysis failed.")',
        1,
    )
    return source


def set_platform_status(source: str, name: str, expression: str) -> str:
    pattern = rf'(name:\s*"{re.escape(name)}".*?status:\s*)"Active"'
    updated, _ = re.subn(pattern, rf'\1{expression}', source, count=1, flags=re.S)
    return updated


def patch_home(source: str) -> str:
    if 'import React, { useEffect, useState } from "react";' not in source:
        source = source.replace(
            'import React, { useState } from "react";',
            'import React, { useEffect, useState } from "react";',
            1,
        )

    if "const [feedHealth, setFeedHealth]" not in source:
        state_pattern = r'(?m)^(?P<indent>[ \t]+)const \[scanError, setScanError\] = useState\(""\);'

        def add_health(match: re.Match[str]) -> str:
            indent = match.group("indent")
            lines = [
                f'{indent}const [scanError, setScanError] = useState("");',
                f'{indent}const [feedHealth, setFeedHealth] = useState<Record<string, string>>({{}});',
                "",
                f'{indent}useEffect(() => {{',
                f'{indent}  let cancelled = false;',
                f'{indent}  api.getApiHealth()',
                f'{indent}    .then((data: any) => {{',
                f'{indent}      const next: Record<string, string> = {{}};',
                f'{indent}      for (const item of data?.apis ?? []) {{',
                f'{indent}        const status = String(item?.status ?? "unknown").toLowerCase();',
                f'{indent}        next[String(item?.name ?? "")] =',
                f'{indent}          status === "online" ? "Online" :',
                f'{indent}          status === "degraded" ? "Degraded" :',
                f'{indent}          status === "offline" ? "Offline" :',
                f'{indent}          status === "unavailable" ? "Not configured" : "Unknown";',
                f'{indent}      }}',
                f'{indent}      if (!cancelled) setFeedHealth(next);',
                f'{indent}    }})',
                f'{indent}    .catch(() => {{',
                f'{indent}      if (!cancelled) setFeedHealth({{ __error: "Offline" }});',
                f'{indent}    }});',
                f'{indent}  return () => {{ cancelled = true; }};',
                f'{indent}}}, []);',
            ]
            return "\n".join(lines)

        source, _ = re.subn(state_pattern, add_health, source, count=1)

    # Remove the forced six-second delay regardless of surrounding comments.
    source, _ = re.subn(
        r'(?ms)^[ \t]*const minDelay = new Promise<void>\(r => setTimeout\(r, 6000\)\);\s*^[ \t]*const \[result\] = await Promise\.all\(\[\s*^[ \t]*api\.analyzeIndicator\(indicator, type\),\s*^[ \t]*minDelay,\s*^[ \t]*\]\);',
        '      const result = await api.analyzeIndicator(indicator, type);',
        source,
        count=1,
    )

    mappings = {
        "VirusTotal": 'feedHealth["VirusTotal"] || (feedHealth.__error ? "Offline" : "Checking")',
        "AbuseIPDB": 'feedHealth["AbuseIPDB"] || (feedHealth.__error ? "Offline" : "Checking")',
        "GreyNoise": 'feedHealth["GreyNoise"] || (feedHealth.__error ? "Offline" : "Checking")',
        "AlienVault OTX": 'feedHealth["AlienVault"] || (feedHealth.__error ? "Offline" : "Checking")',
        "URLScan.io": 'feedHealth["URLScan.io"] || "Not checked"',
        "Local OSINT Engine": '"Online"',
    }
    for name, expression in mappings.items():
        source = set_platform_status(source, name, expression)

    return source

def main() -> int:
    args = parse_args()
    patcher = Patcher(Path(args.repo), args.dry_run, args.force)
    try:
        patcher.require_layout()
        patcher.transform("backend/main.py", patch_main)
        patcher.transform("backend/routers/ip.py", patch_ip)
        patcher.transform("backend/routers/domain.py", patch_domain)
        patcher.transform("backend/routers/url.py", patch_url)
        patcher.transform("frontend/app/page.tsx", patch_home)
        patcher.write("backend/core/validators.py", VALIDATORS_PY)
        patcher.write("backend/tests/test_validators.py", VALIDATOR_TESTS)
        patcher.write("frontend/app/results/bulk/page.tsx", BULK_PAGE_TSX)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    for message in patcher.messages:
        print(message)
    if patcher.changed:
        print(f"\nChanged {len(patcher.changed)} file(s).")
        print(f"Backup: {patcher.backup_root}")
    elif args.dry_run:
        print("\nDry run completed; no files were written.")
    else:
        print("\nNo changes were required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
