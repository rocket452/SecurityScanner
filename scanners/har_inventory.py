import json
import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


def _safe_read_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _host_in_scope(host: str, scope: str) -> bool:
    host = (host or "").lower().strip(".")
    scope = (scope or "").lower().strip()
    if not host or not scope:
        return False
    if scope.startswith(("http://", "https://")):
        scope = urllib.parse.urlparse(scope).netloc.lower().strip(".")
    scope = scope.strip(".")
    if host == scope:
        return True
    return host.endswith("." + scope)


def _is_in_scope(url: str, scopes: Sequence[str]) -> bool:
    try:
        host = urllib.parse.urlparse(url).netloc.lower().strip(".")
    except Exception:
        return False
    return any(_host_in_scope(host, s) for s in scopes)


def _parse_query_param_names(request: Dict[str, Any], url: str) -> Set[str]:
    names: Set[str] = set()
    for q in request.get("queryString") or []:
        n = (q or {}).get("name")
        if n:
            names.add(str(n))
    if names:
        return names
    try:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        return set(qs.keys())
    except Exception:
        return set()


def _parse_body_param_names(request: Dict[str, Any]) -> Set[str]:
    names: Set[str] = set()
    post = request.get("postData") or {}
    for p in post.get("params") or []:
        n = (p or {}).get("name")
        if n:
            names.add(str(n))
    if names:
        return names

    mime = (post.get("mimeType") or "").lower()
    text = post.get("text")
    if not text or not isinstance(text, str):
        return set()

    # x-www-form-urlencoded
    if "application/x-www-form-urlencoded" in mime:
        try:
            parsed = urllib.parse.parse_qs(text, keep_blank_values=True)
            return set(parsed.keys())
        except Exception:
            return set()

    # JSON
    if "application/json" in mime:
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return {str(k) for k in obj.keys()}
        except Exception:
            return set()

    return set()


def _header_name_set(request: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()
    for h in request.get("headers") or []:
        name = (h or {}).get("name")
        if name:
            out.add(str(name).lower())
    return out


def _redact_url(url: str) -> str:
    try:
        p = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
        if not qs:
            return url
        redacted = urllib.parse.urlencode([(k, "<redacted>") for k, _ in qs], doseq=True)
        return p._replace(query=redacted).geturl()
    except Exception:
        return url


@dataclass(frozen=True)
class InventoryKey:
    method: str
    scheme: str
    host: str
    path: str


@dataclass
class InventoryItem:
    key: InventoryKey
    count: int = 0
    sample_url: str = ""
    query_params: Set[str] = field(default_factory=set)
    body_params: Set[str] = field(default_factory=set)
    header_names: Set[str] = field(default_factory=set)
    has_cookie: bool = False
    has_auth: bool = False


def build_inventory_from_har(
    har_path: str,
    scopes: Sequence[str],
    include_headers: bool = False,
    redact: bool = True,
) -> List[InventoryItem]:
    data = _safe_read_json(har_path)
    entries = (((data.get("log") or {}).get("entries")) or [])

    inv: Dict[InventoryKey, InventoryItem] = {}

    for e in entries:
        req = (e or {}).get("request") or {}
        method = (req.get("method") or "GET").upper()
        url = req.get("url") or ""
        if not url or not url.startswith(("http://", "https://")):
            continue
        if scopes and not _is_in_scope(url, scopes):
            continue

        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        key = InventoryKey(method=method, scheme=parsed.scheme, host=parsed.netloc, path=path)

        item = inv.get(key)
        if not item:
            item = InventoryItem(key=key)
            inv[key] = item

        item.count += 1
        if not item.sample_url:
            item.sample_url = _redact_url(url) if redact else url

        item.query_params |= _parse_query_param_names(req, url)
        item.body_params |= _parse_body_param_names(req)

        if include_headers:
            hn = _header_name_set(req)
            item.header_names |= hn
            item.has_cookie = item.has_cookie or ("cookie" in hn)
            item.has_auth = item.has_auth or ("authorization" in hn) or ("x-api-key" in hn)
        else:
            hn = _header_name_set(req)
            item.has_cookie = item.has_cookie or ("cookie" in hn)
            item.has_auth = item.has_auth or ("authorization" in hn) or ("x-api-key" in hn)

    items = list(inv.values())
    items.sort(key=lambda x: (x.key.host.lower(), x.key.path, x.key.method))
    return items


def inventory_to_text(items: Sequence[InventoryItem]) -> str:
    lines: List[str] = []
    lines.append(f"HAR inventory generated: {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"Endpoints: {len(items)}")
    lines.append("")
    for it in items:
        qp = ", ".join(sorted(it.query_params)) if it.query_params else "-"
        bp = ", ".join(sorted(it.body_params)) if it.body_params else "-"
        flags = []
        if it.has_cookie:
            flags.append("cookie")
        if it.has_auth:
            flags.append("auth")
        flag_s = ",".join(flags) if flags else "-"
        lines.append(f"{it.key.method:6} {it.key.scheme}://{it.key.host}{it.key.path}  hits={it.count}  flags={flag_s}")
        lines.append(f"  sample: {it.sample_url}")
        lines.append(f"  query:  {qp}")
        lines.append(f"  body:   {bp}")
        if it.header_names:
            lines.append(f"  hdrs:   {', '.join(sorted(it.header_names))}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def inventory_to_json(items: Sequence[InventoryItem]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for it in items:
        out.append(
            {
                "method": it.key.method,
                "scheme": it.key.scheme,
                "host": it.key.host,
                "path": it.key.path,
                "hits": it.count,
                "sample_url": it.sample_url,
                "query_params": sorted(it.query_params),
                "body_params": sorted(it.body_params),
                "header_names": sorted(it.header_names),
                "has_cookie": it.has_cookie,
                "has_auth": it.has_auth,
            }
        )
    return out


def write_inventory_outputs(
    items: Sequence[InventoryItem],
    text_out: Optional[str],
    json_out: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
    text_path = None
    json_path = None

    if text_out:
        Path(text_out).parent.mkdir(parents=True, exist_ok=True)
        Path(text_out).write_text(inventory_to_text(items), encoding="utf-8")
        text_path = text_out

    if json_out:
        Path(json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(json_out).write_text(json.dumps(inventory_to_json(items), indent=2), encoding="utf-8")
        json_path = json_out

    return text_path, json_path

