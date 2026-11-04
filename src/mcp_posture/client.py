"""Minimal MCP protocol prober over the hardened HTTP layer.

Era detection mirrors the official SDK: probe ``server/discover`` (2026-07-28 stateless
envelope); anything that is not a modern answer falls back to the ``initialize`` handshake
(≤ 2025-11-25); if the POST endpoint rejects that too, try the legacy HTTP+SSE GET stream.
Only list and read operations are sent; no tool is ever called. Servers declaring the Skills
extension (SEP-2640) also get ``skills/list``, ``skills/get`` and ``resources/read`` of skill
files, within a byte budget.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.parse import urljoin, urlsplit

from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS, LATEST_HANDSHAKE_VERSION

from mcp_posture import __version__
from mcp_posture import skills as S
from mcp_posture.context import (
    Challenge,
    McpProbe,
    SkillFile,
    SkillsProbe,
    SurfaceItem,
    SurfaceKind,
    freeze,
)
from mcp_posture.discovery import parse_www_authenticate
from mcp_posture.models import SpecRevision
from mcp_posture.net import Fetcher, HttpExchange, StopFn

MODERN_VERSION = SpecRevision.R2026_07_28.value
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPS = "io.modelcontextprotocol/clientCapabilities"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
CLIENT_INFO = {"name": "mcp-posture", "version": __version__}
ACCEPT = "application/json, text/event-stream"
MAX_PAGES = 20
_IDENTITY: dict[str, str] = {
    "tool": "name",
    "prompt": "name",
    "resource": "uri",
    "resource_template": "uriTemplate",
}
SSE_READ_TIMEOUT = 5.0
MAX_ENDPOINT_REDIRECTS = 3
SSE_FIELDS = (b"data:", b"event:", b"id:", b":", b"retry:")

LISTS: tuple[tuple[str, str, SurfaceKind, str], ...] = (
    ("tools/list", "tools", "tool", "tools"),
    ("prompts/list", "prompts", "prompt", "prompts"),
    ("resources/list", "resources", "resource", "resources"),
    ("resources/templates/list", "resourceTemplates", "resource_template", "resources"),
)


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    return (pa.scheme, (pa.hostname or "").lower(), pa.port) == (
        pb.scheme,
        (pb.hostname or "").lower(),
        pb.port,
    )


def parse_rpc_body(ex: HttpExchange, request_id: int | None = None) -> dict[str, Any] | None:
    """Extract the JSON-RPC response from a JSON or SSE body."""
    if ex.content_type == "text/event-stream":
        for data in iter_sse_data(ex.text):
            try:
                msg = json.loads(data)
            except (ValueError, RecursionError):
                continue
            if not isinstance(msg, dict) or not ("result" in msg or "error" in msg):
                continue
            if request_id is None or msg.get("id") == request_id:
                return dict(msg)
        return None
    doc = ex.json()
    return doc if isinstance(doc, dict) else None


# 2026-07-28 Streamable HTTP: these requests MUST mirror params.name / params.uri in `Mcp-Name`
# (servers answer -32020 HeaderMismatch otherwise).
_NAME_SOURCES = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}
_SENTINEL = re.compile(r"^=\?base64\?.*\?=$")


def header_value(value: str) -> str:
    """Plain when the value is header-safe ASCII, else the spec's Base64 sentinel form."""
    safe = (
        value == value.strip()
        and all(c == "\t" or 0x20 <= ord(c) <= 0x7E for c in value)
        and not _SENTINEL.match(value)
    )
    if safe:
        return value
    return "=?base64?" + base64.b64encode(value.encode("utf-8")).decode("ascii") + "?="


def _name_header(method: str, params: dict[str, Any] | None) -> str | None:
    key = _NAME_SOURCES.get(method)
    value = (params or {}).get(key) if key else None
    return header_value(value) if isinstance(value, str) else None


def _rpc_error(ex: HttpExchange, msg: dict[str, Any] | None) -> str:
    """Short, server-neutral description of a failed JSON-RPC call."""
    error = (msg or {}).get("error")
    if isinstance(error, dict) and isinstance(error.get("code"), int):
        return f"JSON-RPC error {error['code']}"
    if ex.error:
        return ex.error
    return f"HTTP {ex.status}" if ex.status is not None else "no response"


def iter_sse_data(text: str) -> list[str]:
    events: list[str] = []
    data: list[str] = []
    for line in text.replace("\r\n", "\n").split("\n"):
        if line == "":
            if data:
                events.append("\n".join(data))
                data = []
        elif line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))
    if data:
        events.append("\n".join(data))
    return events


def iter_sse_events(text: str) -> list[tuple[str, str]]:
    """(event, data) pairs; event defaults to ``message``."""
    out: list[tuple[str, str]] = []
    event, data = "message", list[str]()
    for line in text.replace("\r\n", "\n").split("\n"):
        if line == "":
            if data:
                out.append((event, "\n".join(data)))
            event, data = "message", []
        elif line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))
    return out


def _sse_has_response(request_id: int) -> StopFn:
    """Stop reading an SSE body once the response to ``request_id`` has arrived.

    Stateful: each call parses only the events completed since the previous call, so a
    server trickling a large stream costs linear, not quadratic, time.
    """
    done = 0  # bytes of the buffer already parsed (always at an event boundary)

    def stop(buf: bytes) -> bool:
        nonlocal done
        if done == 0 and not buf[:64].lstrip().startswith(SSE_FIELDS):
            return False
        boundary = max(buf.rfind(b"\n\n") + 2, buf.rfind(b"\r\n\r\n") + 4, 0)
        if boundary <= done:
            return False
        events = buf[done:boundary].decode("utf-8", errors="ignore")
        done = boundary
        for data in iter_sse_data(events):
            try:
                msg = json.loads(data)
            except (ValueError, RecursionError):
                continue
            if isinstance(msg, dict) and msg.get("id") == request_id:
                return True
        return False

    return stop


def _endpoint_event(buf: bytes) -> bool:
    return b"event: endpoint" in buf or b"event:endpoint" in buf


@dataclass
class _State:
    """Mutable accumulator; frozen into :class:`McpProbe` at the end."""

    probe: McpProbe = field(default_factory=McpProbe)
    session_id: str | None = None
    version: str | None = None
    next_id: int = 1


class McpClient:
    def __init__(self, fetcher: Fetcher, url: str, token: str | None = None) -> None:
        self.fetcher = fetcher
        self.url = url
        self.origin_url = url
        self.token = token

    async def probe(self) -> McpProbe:
        st = _State()
        await self._run(st, authenticated=False)
        if st.probe.auth_required and self.token:
            st2 = _State(probe=st.probe)
            await self._run(st2, authenticated=True)
            st = st2
        return st.probe

    async def _run(self, st: _State, authenticated: bool) -> None:
        modern = await self._try_modern(st, authenticated)
        if modern is None:
            handshake = await self._try_handshake(st, authenticated)
            if handshake is None and not st.probe.auth_required:
                await self._try_legacy_sse(st, authenticated)
        if st.probe.era != "unknown" and not (st.probe.auth_required and not authenticated):
            await self._list_surface(st, authenticated)
            if st.probe.era == "modern" and S.declaration(st.probe.capabilities) is not None:
                await self._list_skills(st, authenticated)
        if st.session_id:
            await self._delete_session(st, authenticated)

    def _headers(
        self, st: _State, method: str, authenticated: bool, params: dict[str, Any] | None = None
    ) -> dict[str, str]:
        h = {"Accept": ACCEPT, "Content-Type": "application/json"}
        if st.version:
            h["MCP-Protocol-Version"] = st.version
        if st.probe.era == "modern" or method == "server/discover":
            h["Mcp-Method"] = method
            name = _name_header(method, params)
            if name is not None:
                h["Mcp-Name"] = name
        if st.session_id:
            h["Mcp-Session-Id"] = st.session_id
        if authenticated and self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    async def _rpc(
        self,
        st: _State,
        method: str,
        params: dict[str, Any] | None,
        authenticated: bool,
        *,
        notification: bool = False,
        max_bytes: int | None = None,
    ) -> tuple[HttpExchange, dict[str, Any] | None]:
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        rid = None
        if not notification:
            rid = st.next_id
            st.next_id += 1
            body["id"] = rid
        if params is not None:
            body["params"] = params
        for _ in range(MAX_ENDPOINT_REDIRECTS + 1):
            ex = await self.fetcher.request(
                "POST",
                self.url,
                headers=self._headers(st, method, authenticated, params),
                json_body=body,
                follow_redirects=False,
                stop_when=_sse_has_response(rid) if rid is not None else None,
                read_timeout=SSE_READ_TIMEOUT,
                max_bytes=max_bytes,
            )
            if not self._follow_endpoint_redirect(st, ex):
                break
        if ex.status == 401:
            self._record_challenge(st, ex, authenticated)
        return ex, (parse_rpc_body(ex, rid) if rid is not None else None)

    def _follow_endpoint_redirect(self, st: _State, ex: HttpExchange) -> bool:
        """MCP clients follow a 307/308 on the endpoint (e.g. a framework adding a trailing
        slash). Follow it too, within the target's origin only: credentials never leave it.
        Every redirect is recorded for MCPP-TRN11."""
        location = ex.header("location")
        if ex.status not in (307, 308) or not location:
            return False
        nxt = urljoin(self.url, location)
        hop = (ex.status, nxt)
        if hop not in st.probe.endpoint_redirects:
            st.probe = replace(st.probe, endpoint_redirects=(*st.probe.endpoint_redirects, hop))
        if not same_origin(nxt, self.origin_url) or nxt == self.url:
            return False
        self.url = nxt
        st.probe = replace(st.probe, endpoint_url=nxt)
        return True

    def _record_challenge(self, st: _State, ex: HttpExchange, authenticated: bool) -> None:
        if authenticated:
            st.probe = replace(st.probe, token_rejected=True)
            return
        challenges: tuple[Challenge, ...] = parse_www_authenticate(
            ex.header_all("www-authenticate")
        )
        if not st.probe.auth_required:
            st.probe = replace(
                st.probe, auth_required=True, unauth_exchange=ex, challenges=challenges
            )

    def _modern_meta(self) -> dict[str, Any]:
        return {
            "_meta": {
                META_PROTOCOL_VERSION: MODERN_VERSION,
                META_CLIENT_INFO: CLIENT_INFO,
                META_CLIENT_CAPS: {},
            }
        }

    async def _try_modern(self, st: _State, authenticated: bool) -> bool | None:
        st.version = MODERN_VERSION
        ex, msg = await self._rpc(st, "server/discover", self._modern_meta(), authenticated)
        result = (msg or {}).get("result")
        if ex.status == 401:
            # Unknown era until authenticated; the handshake attempt below may tell us more.
            st.version = None
            return None
        if isinstance(result, dict) and MODERN_VERSION in (result.get("supportedVersions") or []):
            meta = result.get("_meta") or {}
            st.probe = replace(
                st.probe,
                transport="streamable-http",
                era="modern",
                negotiated_version=MODERN_VERSION,
                server_info=freeze(meta.get(META_SERVER_INFO)) if isinstance(meta, dict) else None,
                capabilities=freeze(caps)
                if isinstance(caps := result.get("capabilities"), dict)
                else None,
            )
            sid = ex.header("mcp-session-id")
            if sid:
                st.probe = replace(st.probe, session_ids=(*st.probe.session_ids, sid))
            return True
        st.version = None
        return None

    async def _initialize(
        self, st: _State, authenticated: bool
    ) -> tuple[HttpExchange, dict[str, Any] | None]:
        params = {
            "protocolVersion": LATEST_HANDSHAKE_VERSION,
            "capabilities": {},
            "clientInfo": CLIENT_INFO,
        }
        return await self._rpc(st, "initialize", params, authenticated)

    async def _try_handshake(self, st: _State, authenticated: bool) -> bool | None:
        ex, msg = await self._initialize(st, authenticated)
        result = (msg or {}).get("result")
        if not isinstance(result, dict):
            return None
        version = result.get("protocolVersion")
        sid = ex.header("mcp-session-id")
        st.session_id = sid
        st.version = version if version in HANDSHAKE_PROTOCOL_VERSIONS else LATEST_HANDSHAKE_VERSION
        sids = (*st.probe.session_ids, sid) if sid else st.probe.session_ids
        st.probe = replace(
            st.probe,
            transport="streamable-http",
            era="handshake",
            negotiated_version=version if isinstance(version, str) else None,
            server_info=freeze(result.get("serverInfo")),
            session_ids=sids,
        )
        await self._rpc(st, "notifications/initialized", None, authenticated, notification=True)
        if sid and len(st.probe.session_ids) < 2:
            # A second session lets TRN08 compare identifiers; it is closed right away.
            second = _State(version=st.version, next_id=100)
            ex2, _ = await self._initialize(second, authenticated)
            sid2 = ex2.header("mcp-session-id")
            if sid2:
                st.probe = replace(st.probe, session_ids=(*st.probe.session_ids, sid2))
                second.session_id = sid2
                await self._delete_session(second, authenticated)
        return True

    async def _try_legacy_sse(self, st: _State, authenticated: bool) -> None:
        headers = {"Accept": "text/event-stream"}
        if authenticated and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        ex = await self.fetcher.request(
            "GET",
            self.url,
            headers=headers,
            follow_redirects=False,
            stop_when=_endpoint_event,
            read_timeout=SSE_READ_TIMEOUT,
            max_bytes=65_536,
        )
        if ex.status == 401:
            self._record_challenge(st, ex, authenticated)
            return
        if ex.content_type != "text/event-stream":
            return
        for event, data in iter_sse_events(ex.text + "\n\n"):
            if event == "endpoint":
                st.probe = replace(st.probe, transport="legacy-sse", legacy_endpoint=data.strip())
                return

    async def _list_surface(self, st: _State, authenticated: bool) -> None:
        items: list[SurfaceItem] = []
        errors: list[str] = list(st.probe.errors)
        listed = False
        for method, key, kind, _cap in LISTS:
            cursor: str | None = None
            for _ in range(MAX_PAGES):
                params: dict[str, Any] = self._modern_meta() if st.probe.era == "modern" else {}
                if cursor:
                    params["cursor"] = cursor
                ex, msg = await self._rpc(st, method, params or None, authenticated)
                result = (msg or {}).get("result")
                if not isinstance(result, dict):
                    if ex.status not in (None, 200) or (msg or {}).get("error"):
                        errors.append(f"{method}: HTTP {ex.status}")
                    break
                listed = True
                for raw in result.get(key) or []:
                    if isinstance(raw, dict):
                        # Resources are identified by URI; names may collide.
                        name = raw.get(_IDENTITY[kind]) or raw.get("name") or "?"
                        items.append(SurfaceItem(kind=kind, name=str(name), definition=freeze(raw)))
                cursor = result.get("nextCursor")
                if not isinstance(cursor, str) or not cursor:
                    break
        st.probe = replace(
            st.probe,
            surface=tuple(items),
            surface_listed=listed,
            surface_listed_unauthenticated=listed and not authenticated,
            errors=tuple(errors),
        )

    async def _skills_rpc(
        self, st: _State, method: str, extra: dict[str, Any], authenticated: bool, **kw: Any
    ) -> tuple[HttpExchange, dict[str, Any] | None]:
        return await self._rpc(st, method, {**self._modern_meta(), **extra}, authenticated, **kw)

    async def _list_skills(self, st: _State, authenticated: bool) -> None:
        """SEP-2640 surface: entries from ``skills/list``, one ``skills/get`` on a listed skill
        and one on an unknown URI, then ``resources/read`` of skill files within the budget.
        Everything is a read; nothing is executed or installed."""
        settings = S.declaration(st.probe.capabilities)
        probe = SkillsProbe(declared=True, settings=freeze(dict(settings or {})))
        entries: list[dict[str, Any]] = []
        pages: list[Any] = []
        cursor: str | None = None
        for _ in range(MAX_PAGES):
            ex, msg = await self._skills_rpc(
                st, "skills/list", {"cursor": cursor} if cursor else {}, authenticated
            )
            result = (msg or {}).get("result")
            if not isinstance(result, dict):
                probe = replace(probe, list_error=_rpc_error(ex, msg))
                break
            probe = replace(probe, list_ok=True)
            pages.append(freeze({k: v for k, v in result.items() if k != "skills"}))
            entries.extend(e for e in result.get("skills") or [] if isinstance(e, dict))
            cursor = result.get("nextCursor")
            if not isinstance(cursor, str) or not cursor:
                break
        probe = replace(probe, pages=tuple(pages), entries=tuple(freeze(e) for e in entries))

        first = next((e["uri"] for e in entries if isinstance(e.get("uri"), str)), None)
        if first is not None:
            ex, msg = await self._skills_rpc(st, "skills/get", {"uri": first}, authenticated)
            result = (msg or {}).get("result")
            ok = isinstance(result, dict) and isinstance(result.get("skill"), dict)
            if ok and isinstance(result, dict):
                pages.append(freeze({k: v for k, v in result.items() if k != "skill"}))
            probe = replace(
                probe,
                pages=tuple(pages),
                get_ok=ok,
                get_error=None if ok else _rpc_error(ex, msg),
            )
        ex, msg = await self._skills_rpc(
            st, "skills/get", {"uri": S.UNKNOWN_SKILL_URI}, authenticated
        )
        error = (msg or {}).get("error")
        code = error.get("code") if isinstance(error, dict) else None
        probe = replace(
            probe,
            unknown_get_code=code if isinstance(code, int) else None,
            unknown_get_answered=isinstance((msg or {}).get("result"), dict),
        )

        probe = replace(
            probe, files=tuple(await self._read_skill_files(st, entries, authenticated))
        )
        surface = tuple(
            SurfaceItem(kind="skill", name=S.label(e["uri"]), definition=freeze(e))
            for e in entries
            if isinstance(e.get("uri"), str)
        )
        st.probe = replace(st.probe, skills=probe, surface=(*st.probe.surface, *surface))

    async def _read_skill_files(
        self, st: _State, entries: list[dict[str, Any]], authenticated: bool
    ) -> list[SkillFile]:
        files: list[SkillFile] = []
        budget = S.MAX_TARGET_BYTES
        # JSON escaping or base64 inflates the body; leave room around the raw cap.
        body_cap = S.MAX_FILE_BYTES * 2 + 16_384
        for entry in entries[: S.MAX_SKILLS_READ]:
            skill_uri = entry.get("uri")
            if not isinstance(skill_uri, str):
                continue
            manifest = S.resources_of(entry)
            listed: list[tuple[str, int | None, str | None]] = (
                [
                    (r["uri"], r.get("size") if isinstance(r.get("size"), int) else None, None)
                    for r in manifest
                    if isinstance(r.get("uri"), str)
                ]
                if manifest is not None
                else [(skill_uri, None, None)]
            )
            # SKILL.md first, so the budget always covers it.
            listed.sort(key=lambda r: r[0] != skill_uri)
            for uri, size, mime in listed:
                if not S.is_text(uri, mime) and uri != skill_uri:
                    files.append(SkillFile(uri, skill_uri, mime_type=mime, skipped="not text"))
                    continue
                if size is not None and size > S.MAX_FILE_BYTES:
                    files.append(SkillFile(uri, skill_uri, skipped=f"{size} bytes, over budget"))
                    continue
                if budget <= 0:
                    files.append(SkillFile(uri, skill_uri, skipped="scan budget exhausted"))
                    continue
                ex, msg = await self._skills_rpc(
                    st, "resources/read", {"uri": uri}, authenticated, max_bytes=body_cap
                )
                result = (msg or {}).get("result")
                if ex.truncated:
                    files.append(SkillFile(uri, skill_uri, skipped="response over budget"))
                    continue
                if not isinstance(result, dict):
                    files.append(SkillFile(uri, skill_uri, error=_rpc_error(ex, msg)))
                    continue
                data, text, err = S.decode_contents(result, uri)
                contents = result.get("contents")
                head = contents[0] if isinstance(contents, list) and contents else {}
                mime = head.get("mimeType") if isinstance(head, dict) else None
                if data is None:
                    files.append(SkillFile(uri, skill_uri, mime_type=mime, error=err))
                    continue
                budget -= len(data)
                if len(data) > S.MAX_FILE_BYTES:
                    text = None  # still hashed for SKL04, but too long to scan as text
                files.append(
                    SkillFile(
                        uri,
                        skill_uri,
                        data=data,
                        text=text,
                        mime_type=mime if isinstance(mime, str) else None,
                    )
                )
        return files

    async def _delete_session(self, st: _State, authenticated: bool) -> None:
        headers = self._headers(st, "", authenticated)
        headers.pop("Content-Type", None)
        await self.fetcher.request("DELETE", self.url, headers=headers, follow_redirects=False)
