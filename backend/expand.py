"""Find out where a short link (bit.ly, tinyurl, t.co...) really goes.

We ask the link-shortening company, and only the link-shortening company.
One HEAD request per hop, redirects NOT followed: we read the Location header
the shortener sends back and stop. If that points at another shortener we
ask that one too (up to MAX_HOPS). We never send a request to the
destination itself, so the "we never open your links" promise holds: the
scam site never sees us.

Safety rails:
- Only hosts in SHORTENERS are ever contacted, over HTTPS. A Location that
  points anywhere else is recorded, not fetched, so this can't be turned into
  a way to make our Lambda call arbitrary or internal addresses.
- Short timeouts and a cap on how many links one message can expand.
- Any failure means "couldn't check", and the message keeps its
  "you can't see where this goes" warning. Failing never makes a verdict
  look safer.
"""

from __future__ import annotations

import http.client
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, TypedDict
from urllib.parse import urljoin, urlsplit

from backend.checks import SHORTENERS, registrable_domain

logger = logging.getLogger("isthislegit.expand")

MAX_HOPS = 4
MAX_LINKS = 5
TIMEOUT_S = 2.5
USER_AGENT = "IsThisLegit/1.0 (link check; reads redirect only, never visits destination)"
REDIRECTS = {301, 302, 303, 307, 308}


class Expansion(TypedDict):
    short: str  # the link as it appeared in the message
    final: str | None  # where it really goes, or None if we couldn't tell
    status: str  # "ok" | "dead" | "blocked" | "failed"


def is_shortener(host: str) -> bool:
    host = host.lower()
    return host in SHORTENERS or registrable_domain(host) in SHORTENERS


def _head(host: str, path: str) -> tuple[int, str | None]:
    conn = http.client.HTTPSConnection(host, timeout=TIMEOUT_S)
    try:
        conn.request("HEAD", path, headers={"User-Agent": USER_AGENT})
        resp = conn.getresponse()
        return resp.status, resp.getheader("Location")
    finally:
        conn.close()


def expand_one(url: str, head: Callable[[str, str], tuple[int, str | None]] = _head) -> Expansion:
    current = url
    for _ in range(MAX_HOPS):
        parts = urlsplit(current)
        host = (parts.hostname or "").lower()
        if not is_shortener(host):
            # Left shortener-land: this is the destination. Don't touch it.
            return {"short": url, "final": current, "status": "ok"}
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        try:
            status, location = head(host, path)
        except (OSError, http.client.HTTPException) as exc:
            logger.info("expand failed for %s: %s", host, type(exc).__name__)
            return {"short": url, "final": None, "status": "failed"}
        if status in REDIRECTS and location:
            nxt = urljoin(current, location)
            nxt_parts = urlsplit(nxt)
            # Bitly and friends send flagged links to their own warning page.
            if is_shortener(nxt_parts.hostname or "") and any(
                w in nxt_parts.path.lower() for w in ("warning", "blocked", "spam", "malware", "phishing")
            ):
                return {"short": url, "final": None, "status": "blocked"}
            # Redirect to the shortener's own preview or home page: the real
            # destination isn't in the headers. Treat as unknown.
            if is_shortener(nxt_parts.hostname or "") and registrable_domain(nxt_parts.hostname or "") == registrable_domain(host):
                if nxt_parts.path.strip("/") in ("", "404") or "preview" in nxt_parts.path.lower():
                    return {"short": url, "final": None, "status": "failed"}
            current = nxt
            continue
        if status in (404, 410):
            return {"short": url, "final": None, "status": "dead"}
        return {"short": url, "final": None, "status": "failed"}
    return {"short": url, "final": None, "status": "failed"}


def expand_links(urls: list[str], head: Callable[[str, str], tuple[int, str | None]] = _head) -> dict[str, Expansion]:
    """Expand every shortened URL in parallel. Returns {short_url: Expansion}."""
    todo = []
    for u in urls:
        host = (urlsplit(u).hostname or "").lower()
        if is_shortener(host) and u not in todo:
            todo.append(u)
    todo = todo[:MAX_LINKS]
    if not todo:
        return {}
    with ThreadPoolExecutor(max_workers=len(todo)) as pool:
        results = list(pool.map(lambda u: expand_one(u, head), todo))
    return {r["short"]: r for r in results}
