"""Helpers for the Skills extension (SEP-2640, ``io.modelcontextprotocol/skills``).

Pure functions over server-provided data: entry validation, frontmatter parsing, and file
classification. Collection lives in :mod:`mcp_posture.client`, verdicts in ``checks/skl.py``.
Everything here treats its input as hostile: sizes are capped and YAML aliases are refused.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping
from typing import Any

import yaml

EXTENSION = "io.modelcontextprotocol/skills"
SKILL_FILE = "SKILL.md"

# SEP-2640 "Limits": what every conforming host accepts.
MAX_RESOURCES = 512
MAX_TOTAL_BYTES = 16_777_216

# Scanner budget: a passive scan reads skill files, but only so much of them.
MAX_SKILLS_READ = 50
MAX_FILE_BYTES = 262_144
MAX_TARGET_BYTES = 4_194_304
FRONTMATTER_MAX_BYTES = 65_536

UNKNOWN_SKILL_URI = "skill://mcp-posture-nonexistent/SKILL.md"

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
# Agent Skills `name`: 1-64 chars, lowercase letters, digits and single inner hyphens.
_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_MAX_NAME = 64
_MAX_DESCRIPTION = 1024

_CODE_EXTENSIONS = frozenset(
    {
        "py", "sh", "bash", "zsh", "fish", "js", "mjs", "cjs", "ts", "mts", "rb", "pl", "php",
        "ps1", "psm1", "bat", "cmd", "vbs", "lua", "go", "rs", "java", "kt", "swift", "c",
        "cc", "cpp", "r", "applescript", "scpt",
    }
)  # fmt: skip
_BINARY_EXTENSIONS = frozenset(
    {"exe", "dll", "so", "dylib", "bin", "jar", "wasm", "msi", "app", "pyc", "class", "elf"}
)
_TEXT_EXTENSIONS = frozenset(
    {"md", "markdown", "txt", "json", "yaml", "yml", "toml", "csv", "xml", "html", "ini", "cfg"}
)
_CODE_MIME = re.compile(
    r"^(text/x-|application/x-)(python|sh|shellscript|ruby|perl|php|powershell|lua)|"
    r"^(text|application)/(javascript|ecmascript|typescript|x-typescript)$",
    re.I,
)
_EXEC_MIME = re.compile(
    r"^application/(x-executable|x-mach-binary|x-msdownload|x-dosexec|x-sharedlib|"
    r"java-archive|wasm|octet-stream)$",
    re.I,
)
_MAGIC = (b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
          b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\x00asm")  # fmt: skip


def declaration(capabilities: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    """The extension's settings object when the server declares it, else ``None``."""
    if not isinstance(capabilities, Mapping):
        return None
    extensions = capabilities.get("extensions")
    if not isinstance(extensions, Mapping):
        return None
    settings = extensions.get(EXTENSION)
    return settings if isinstance(settings, Mapping) else None


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def label(uri: str) -> str:
    """Short, stable name for a skill in locations: ``skill://acme/refunds/SKILL.md`` ->
    ``acme/refunds``. Other schemes keep the full URI (identity is the URI, SEP-2640)."""
    prefix, suffix = "skill://", "/" + SKILL_FILE
    if uri.startswith(prefix) and uri.endswith(suffix) and len(uri) > len(prefix + suffix):
        return uri[len(prefix) : -len(suffix)]
    return uri


def location(uri: str) -> str:
    return f"skill:{label(uri)}"


def skill_root(uri: str) -> str:
    """``skill://a/b/SKILL.md`` -> ``skill://a/b``."""
    return uri[: -len("/" + SKILL_FILE)] if uri.endswith("/" + SKILL_FILE) else uri


def relative_path(skill_uri: str, file_uri: str) -> str:
    root = skill_root(skill_uri) + "/"
    return file_uri[len(root) :] if file_uri.startswith(root) else file_uri


def last_segment(skill_uri: str) -> str:
    root = skill_root(skill_uri)
    path = root.split("://", 1)[-1]
    return path.rstrip("/").rsplit("/", 1)[-1]


def name_problems(name: Any) -> list[str]:
    if not isinstance(name, str) or not name:
        return ["`frontmatter.name` is missing or not a string"]
    out = []
    if len(name) > _MAX_NAME:
        out.append(f"name is {len(name)} characters (max {_MAX_NAME})")
    if not _NAME.match(name):
        out.append(
            f"name {name!r} breaks the Agent Skills rules (lowercase letters, digits and single "
            "inner hyphens)"
        )
    return out


def resources_of(entry: Mapping[str, Any]) -> list[Mapping[str, Any]] | None:
    """The manifest as a list, or ``None`` when it is ``"dynamic"`` or invalid."""
    res = entry.get("resources")
    if isinstance(res, list | tuple):
        return [r for r in res if isinstance(r, Mapping)]
    return None


def is_dynamic(entry: Mapping[str, Any]) -> bool:
    return entry.get("resources") == "dynamic"


def entry_problems(entry: Mapping[str, Any]) -> list[str]:
    """Structural violations of SEP-2640 in one ``Skill`` entry (MCPP-SKL03)."""
    out: list[str] = []
    uri = entry.get("uri")
    if not isinstance(uri, str) or not uri:
        return ["entry has no `uri`"]
    if not uri.endswith("/" + SKILL_FILE):
        out.append(f"`uri` does not name a {SKILL_FILE}")
    fm = entry.get("frontmatter")
    if not isinstance(fm, Mapping):
        out.append("`frontmatter` is missing or not an object")
    else:
        name = fm.get("name")
        out.extend(name_problems(name))
        if isinstance(name, str) and name and last_segment(uri) != name:
            out.append(f"last URI segment {last_segment(uri)!r} differs from name {name!r}")
        desc = fm.get("description")
        if not isinstance(desc, str) or not desc.strip():
            out.append("`frontmatter.description` is missing or empty")
        elif len(desc) > _MAX_DESCRIPTION:
            out.append(f"description is {len(desc)} characters (max {_MAX_DESCRIPTION})")
    raw = entry.get("resources")
    if raw == "dynamic":
        return out
    if not isinstance(raw, list | tuple):
        out.append('`resources` is missing or neither an array nor "dynamic"')
        return out
    root = skill_root(uri) + "/"
    seen: set[str] = set()
    has_skill_md = False
    for i, r in enumerate(raw):
        if not isinstance(r, Mapping):
            out.append(f"resources[{i}] is not an object")
            continue
        ruri = r.get("uri")
        if not isinstance(ruri, str):
            out.append(f"resources[{i}] has no `uri`")
            continue
        if ruri == uri:
            has_skill_md = True
        elif not ruri.startswith(root) or "/../" in ruri or ruri.endswith("/.."):
            out.append(f"{ruri} is outside the skill directory")
        if ruri in seen:
            out.append(f"{ruri} is listed twice")
        seen.add(ruri)
        if not isinstance(r.get("digest"), str) or not _DIGEST.match(r["digest"]):
            out.append(f"{ruri}: digest is not `sha256:` + 64 lowercase hex characters")
        size = r.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            out.append(f"{ruri}: `size` is missing or not a non-negative integer")
    if not has_skill_md:
        out.append(f"the manifest has no entry for {SKILL_FILE} itself")
    return out


def page_problems(page: Mapping[str, Any], method: str) -> list[str]:
    """Missing result fields every ``skills/list`` / ``skills/get`` result must carry."""
    out = []
    if page.get("resultType") != "complete":
        out.append(f'{method}: `resultType` is not "complete"')
    if not isinstance(page.get("ttlMs"), int) or isinstance(page.get("ttlMs"), bool):
        out.append(f"{method}: `ttlMs` is missing")
    if page.get("cacheScope") not in ("public", "private"):
        out.append(f"{method}: `cacheScope` is missing or invalid")
    return out


def extension_of(uri: str) -> str:
    last = uri.rsplit("/", 1)[-1]
    return last.rsplit(".", 1)[-1].lower() if "." in last else ""


def is_code(uri: str, mime: str | None) -> bool:
    if extension_of(uri) in _CODE_EXTENSIONS | _BINARY_EXTENSIONS:
        return True
    if "/scripts/" in uri and extension_of(uri) not in _TEXT_EXTENSIONS:
        return True
    return bool(mime and (_CODE_MIME.match(mime) or _EXEC_MIME.match(mime)))


def is_binary_executable(uri: str, mime: str | None, data: bytes | None = None) -> bool:
    if extension_of(uri) in _BINARY_EXTENSIONS:
        return True
    if mime and _EXEC_MIME.match(mime) and mime.lower() != "application/octet-stream":
        return True
    return bool(data and data.startswith(_MAGIC))


def is_text(uri: str, mime: str | None) -> bool:
    """Whether the scanner reads this file: text a model or a reviewer would read."""
    if is_binary_executable(uri, mime):
        return False
    ext = extension_of(uri)
    if ext in _TEXT_EXTENSIONS or ext in _CODE_EXTENSIONS:
        return True
    if mime:
        m = mime.lower()
        return (
            m.startswith("text/")
            or m.endswith(("+json", "+xml", "/json", "/yaml"))
            or bool(_CODE_MIME.match(m))
        )
    return ext == ""


def decode_contents(result: Mapping[str, Any], uri: str) -> tuple[bytes | None, str | None, str]:
    """(raw bytes, text, error) from a ``resources/read`` result for ``uri``."""
    contents = result.get("contents")
    if not isinstance(contents, list | tuple):
        return None, None, "`contents` is missing"
    item = next(
        (c for c in contents if isinstance(c, Mapping) and c.get("uri") == uri),
        next((c for c in contents if isinstance(c, Mapping)), None),
    )
    if item is None:
        return None, None, "`contents` is empty"
    if isinstance(item.get("text"), str):
        text = item["text"]
        return text.encode("utf-8"), text, ""
    if isinstance(item.get("blob"), str):
        try:
            data = base64.b64decode(item["blob"], validate=True)
        except (binascii.Error, ValueError):
            return None, None, "`blob` is not valid base64"
        try:
            return data, data.decode("utf-8"), ""
        except UnicodeDecodeError:
            return data, None, ""
    return None, None, "content has neither `text` nor `blob`"


class _Loader(yaml.SafeLoader):
    """SafeLoader that keeps timestamps as strings (frontmatter JSON carries them verbatim)."""


_Loader.add_constructor(
    "tag:yaml.org,2002:timestamp",
    lambda loader, node: loader.construct_scalar(node),  # type: ignore[arg-type]
)


def split_frontmatter(text: str) -> str | None:
    """The YAML between the leading ``---`` fences, or ``None`` when there is none."""
    if text.startswith("\ufeff"):
        text = text[1:]
    lines = text.split("\n")
    if not lines or lines[0].rstrip("\r") != "---":
        return None
    for i in range(1, len(lines)):
        if lines[i].rstrip("\r") in ("---", "..."):
            return "\n".join(lines[1:i])
    return None


def parse_frontmatter(text: str) -> tuple[Mapping[str, Any] | None, str | None]:
    """(frontmatter, error). Aliases are refused (YAML bombs), and so is oversized YAML."""
    raw = split_frontmatter(text)
    if raw is None:
        return None, f"{SKILL_FILE} does not start with YAML frontmatter"
    if len(raw.encode("utf-8")) > FRONTMATTER_MAX_BYTES:
        return None, f"frontmatter is larger than {FRONTMATTER_MAX_BYTES} bytes"
    try:
        for event in yaml.parse(raw, Loader=_Loader):
            if isinstance(event, yaml.AliasEvent):
                return None, "frontmatter uses YAML aliases"
        data = yaml.load(raw, Loader=_Loader)  # noqa: S506 - _Loader is a SafeLoader
    except (yaml.YAMLError, RecursionError, ValueError) as e:
        return None, f"frontmatter is not valid YAML ({type(e).__name__})"
    if not isinstance(data, dict):
        return None, "frontmatter is not a mapping"
    return data, None


def json_equal(a: Any, b: Any) -> bool:
    """Equality after a JSON round trip of both sides (tuples vs lists, mapping proxies)."""
    return bool(_norm(a) == _norm(b))


def _norm(v: Any) -> Any:
    if isinstance(v, Mapping):
        return {str(k): _norm(x) for k, x in v.items()}
    if isinstance(v, list | tuple):
        return [_norm(x) for x in v]
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return v
    if isinstance(v, int | float):
        return float(v)
    return str(v)
