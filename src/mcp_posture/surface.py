"""Canonical form and hashing of the tool surface (tools, prompts, resources, templates, skills).

Only security-relevant fields are hashed, so cosmetic server metadata (e.g. cache hints)
does not trigger rug-pull alerts. Unicode is deliberately *not* normalized: an invisible
character added to a description must change the hash.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from mcp_posture.context import ScanContext, SurfaceItem, thaw
from mcp_posture.skills import location, relative_path

HASHED_FIELDS = (
    "name",
    "title",
    "description",
    "inputSchema",
    "outputSchema",
    "annotations",
    "arguments",
    "uri",
    "uriTemplate",
    "mimeType",
    # Skills (SEP-2640): the manifest carries every file's digest, so a pinned skill changes
    # hash when any byte of any file changes, without storing file content in the lock.
    "frontmatter",
    "resources",
)


def canonical(item: SurfaceItem) -> dict[str, Any]:
    raw = thaw(item.definition)
    out = {k: raw[k] for k in HASHED_FIELDS if k in raw}
    if item.kind == "skill" and isinstance(out.get("resources"), list):
        out["resources"] = sorted(
            out["resources"],
            key=lambda r: str(r.get("uri")) if isinstance(r, dict) else canonical_json(r),
        )
    return out


def canonical_json(data: Any, *, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False)
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def item_hash(item: SurfaceItem) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(canonical(item)).encode()).hexdigest()


def texts(item: SurfaceItem) -> list[tuple[str, str]]:
    """(field path, text) pairs a model reads: name, title, descriptions, argument docs.

    Server-controlled definitions may use any JSON type anywhere: nothing here assumes a
    shape, and schema text is collected at any depth (a nesting limit would be an evasion).
    """
    raw = thaw(item.definition)
    if not isinstance(raw, dict):
        return []
    out: list[tuple[str, str]] = []
    if item.kind == "skill":
        # Every frontmatter value reaches the model's skill catalogue, at any depth.
        _schema_texts(raw.get("frontmatter"), "frontmatter", out, every_string=True)
        return out
    for key in ("name", "title", "description"):
        if isinstance(raw.get(key), str):
            out.append((key, raw[key]))
    arguments = raw.get("arguments")
    if isinstance(arguments, list):
        for i, arg in enumerate(arguments):
            if isinstance(arg, dict):
                for key in ("name", "title", "description"):
                    if isinstance(arg.get(key), str):
                        out.append((f"arguments[{i}].{key}", arg[key]))
    for key in ("inputSchema", "outputSchema"):
        _schema_texts(raw.get(key), key, out)
    return out


_TEXT_KEYS = frozenset({"description", "title", "default", "examples", "const", "enum"})


def _schema_texts(
    root: Any, root_path: str, out: list[tuple[str, str]], *, every_string: bool = False
) -> None:
    """Every string a model may read in a JSON Schema: annotations, values, property names.

    With ``every_string``, every string value and key is collected (skill frontmatter)."""
    stack: list[tuple[Any, str, bool]] = [(root, root_path, every_string)]
    while stack:
        node, path, text_value = stack.pop()
        if isinstance(node, str):
            if text_value:
                out.append((path, node))
        elif isinstance(node, dict):
            names = every_string or path.endswith(".properties")  # keys are read too
            for k, v in reversed(list(node.items())):
                if names:
                    out.append((f"{path}[{k!r}]", str(k)))
                keyword = not names and k in _TEXT_KEYS
                stack.append((v, f"{path}.{k}", text_value or keyword))
        elif isinstance(node, list):
            for i in reversed(range(len(node))):
                stack.append((node[i], f"{path}[{i}]", text_value))


def skill_texts(ctx: ScanContext) -> list[tuple[str, str, str]]:
    """(location, field, text) for every skill file read as text (SEP-2640).

    The location is the skill's (``skill:<label>``) and the field is the file's path
    inside the skill, so findings group per skill like they do per tool."""
    return [
        (location(f.skill_uri), relative_path(f.skill_uri, f.uri), f.text)
        for f in ctx.mcp.skills.files
        if f.text is not None
    ]
