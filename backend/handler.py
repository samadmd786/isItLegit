"""Is This Legit? Lambda handler.

POST {"message": "...", "language": "en"} ->
    {"ok": true, "verdict": ..., "findings": [...], "explanation": {...}, "ai": bool}

Layer 1 (checks.py) decides. Layer 2 (explain.py) explains, and if it fails we
fall back to a template, so a parent always gets an answer.

Privacy: messages are never logged or stored. We log rule ids and timings only.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any

from backend.checks import InputError, analyze_text
from backend.expand import expand_links
from backend.explain import LANGUAGES, ExplainError, explain, template_explanation

logger = logging.getLogger("isthislegit")
logger.setLevel(logging.INFO)

HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}


def check(message: str, language: str = "en", client: Any = None, use_ai: bool = True,
          expander: Any = expand_links) -> dict[str, Any]:
    t0 = time.monotonic()
    language = language if language in LANGUAGES else "en"
    try:
        analysis = analyze_text(message, expander=expander)
    except InputError as exc:
        return {"ok": False, "error": str(exc)}

    explanation, ai = None, False
    if use_ai:
        try:
            explanation, ai = explain(message, analysis, language, client=client), True
        except ExplainError as exc:
            logger.warning("explain fallback: %s", str(exc)[:200])
    if explanation is None:
        explanation = template_explanation(analysis)

    logger.info(json.dumps({
        "verdict": analysis["verdict"],
        "rules": [f["rule_id"] for f in analysis["findings"]],
        "expanded": [e["status"] for e in analysis["expanded"]],
        "ai": ai,
        "language": language,
        "ms": int((time.monotonic() - t0) * 1000),
    }))
    return {"ok": True, **analysis, "explanation": explanation, "ai": ai, "language": language}


def _response(status: int, body: dict[str, Any]) -> dict[str, Any]:
    return {"statusCode": status, "headers": HEADERS, "body": json.dumps(body, ensure_ascii=False)}


def lambda_handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    method = event.get("requestContext", {}).get("http", {}).get("method", "POST")
    if method == "OPTIONS":
        return _response(200, {"ok": True})
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8", "replace")
    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    result = check(str(data.get("message", "")), str(data.get("language", "en")))
    return _response(200 if result["ok"] else 400, result)
