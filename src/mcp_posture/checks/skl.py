"""SKL: Agent Skills served over MCP (SEP-2640, ``io.modelcontextprotocol/skills``).

The scanner audits what a server publishes, as a host would see it: entries, manifests,
digests and frontmatter. Poisoning heuristics on skill text are the TOOL checks; rug-pull
pinning of skills is PIN. Every check here is silent when the extension is not declared.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

from mcp_posture import skills as S
from mcp_posture.checks import _refs as R
from mcp_posture.context import ScanContext, SkillsProbe, thaw
from mcp_posture.heuristics import visible
from mcp_posture.models import Evidence, Finding, Severity, SpecRevision, revisions_from
from mcp_posture.registry import check

_REVISIONS = revisions_from(SpecRevision.R2026_07_28)
_EXTENSION_LOCATION = f"extension:{S.EXTENSION}"

_LANGUAGES = {
    "py": "Python", "sh": "shell", "bash": "shell", "zsh": "shell", "fish": "shell",
    "js": "JavaScript", "mjs": "JavaScript", "cjs": "JavaScript", "ts": "TypeScript",
    "mts": "TypeScript", "rb": "Ruby", "pl": "Perl", "php": "PHP", "ps1": "PowerShell",
    "psm1": "PowerShell", "bat": "batch", "cmd": "batch", "vbs": "VBScript", "lua": "Lua",
    "applescript": "AppleScript", "scpt": "AppleScript",
}  # fmt: skip
_PERMISSION_FIELDS = ("allowed-tools", "allowed_tools", "allowedTools", "hooks", "permissions")


def _probe(ctx: ScanContext) -> SkillsProbe | None:
    skills = ctx.mcp.skills
    return skills if skills.declared else None


def _entries(probe: SkillsProbe) -> Iterator[tuple[str, Mapping[str, Any]]]:
    for e in probe.entries:
        uri = e.get("uri")
        if isinstance(uri, str):
            yield uri, e


def _location(uri: str) -> str:
    return S.location(uri)


@check(
    id="MCPP-SKL01",
    title="Skills extension declared without the resources capability",
    severity=Severity.LOW,
    revisions=_REVISIONS,
    references=[R.MCP_SKILLS],
    rationale="""Skill files are served through `resources/read`, and the base protocol
        requires a server that serves resources to declare the `resources` capability.
        SEP-2640 makes it explicit: a server declaring the skills extension MUST also declare
        `resources`. Without it, conforming clients may never read the skill content.""",
    remediation="""Declare `"resources": {}` in the server capabilities next to the
        `io.modelcontextprotocol/skills` extension.""",
)
def skl01(ctx: ScanContext) -> Iterator[Finding]:
    if _probe(ctx) is None:
        return
    caps = ctx.mcp.capabilities or {}
    if "resources" not in caps:
        yield ctx.finding(
            "MCPP-SKL01",
            "The server declares the skills extension but not the `resources` capability.",
            location=_EXTENSION_LOCATION,
        )


@check(
    id="MCPP-SKL02",
    title="Skills methods missing or answering incorrectly",
    severity=Severity.MEDIUM,
    revisions=_REVISIONS,
    references=[R.MCP_SKILLS],
    rationale="""A server declaring the skills extension MUST implement `skills/list` and
        `skills/get`, and MUST answer `skills/get` for a URI it does not serve with error
        `-32602`. Hosts rely on `skills/get` to verify a skill reached by URI and to refresh
        digests; a server answering an unknown URI with a result can make a host load a skill
        that does not exist.""",
    remediation="""Implement both methods (the official SDKs ship them, e.g.
        `SkillsExtension` in the TypeScript SDK) and return `-32602` (Invalid params) for an
        unknown skill URI.""",
)
def skl02(ctx: ScanContext) -> Iterator[Finding]:
    probe = _probe(ctx)
    if probe is None:
        return
    if not probe.list_ok:
        yield ctx.finding(
            "MCPP-SKL02",
            f"skills/list failed ({probe.list_error or 'no result'}).",
            location=_EXTENSION_LOCATION,
            key="list",
        )
    if probe.get_ok is False:
        yield ctx.finding(
            "MCPP-SKL02",
            f"skills/get failed for a listed skill ({probe.get_error or 'no result'}).",
            location=_EXTENSION_LOCATION,
            key="get",
        )
    if probe.unknown_get_answered:
        yield ctx.finding(
            "MCPP-SKL02",
            f"skills/get returned a skill for a URI the server cannot serve "
            f"({S.UNKNOWN_SKILL_URI}).",
            location=_EXTENSION_LOCATION,
            key="unknown",
        )
    elif probe.unknown_get_code is not None and probe.unknown_get_code != -32602:
        missing = probe.unknown_get_code == -32601
        yield ctx.finding(
            "MCPP-SKL02",
            "skills/get is not implemented (-32601 Method not found)."
            if missing
            else f"skills/get answered an unknown skill URI with error "
            f"{probe.unknown_get_code} instead of -32602.",
            location=_EXTENSION_LOCATION,
            key="unknown",
            severity=Severity.MEDIUM if missing else Severity.LOW,
        )


@check(
    id="MCPP-SKL03",
    title="Invalid skill entry",
    severity=Severity.MEDIUM,
    revisions=_REVISIONS,
    references=[R.MCP_SKILLS, R.AGENT_SKILLS],
    rationale="""Hosts build their skill registry, ask for approval and verify content from
        the entries alone. SEP-2640 requires the last URI segment to equal `frontmatter.name`
        (a valid Agent Skills name), a `resources` manifest that is complete (including
        SKILL.md itself) with `sha256:` digests and sizes, files inside the skill directory,
        and `resultType`, `ttlMs` and `cacheScope` on every result. Hosts MUST NOT load an
        entry whose `resources` is missing or invalid.""",
    remediation="""Generate entries with the SDK helpers (they compute digests and sizes),
        name skills after their directory, and keep every file under the skill's path.""",
)
def skl03(ctx: ScanContext) -> Iterator[Finding]:
    probe = _probe(ctx)
    if probe is None:
        return
    page_issues: list[str] = []
    for i, page in enumerate(probe.pages):
        method = "skills/list" if i < len(probe.pages) - (probe.get_ok is True) else "skills/get"
        page_issues.extend(S.page_problems(page, method))
    if page_issues:
        unique = sorted(set(page_issues))
        yield ctx.finding(
            "MCPP-SKL03",
            f"Skills results lack required fields: {'; '.join(unique)}.",
            location=_EXTENSION_LOCATION,
            key="results",
            severity=Severity.LOW,
        )
    unnamed = sum(1 for e in probe.entries if not isinstance(e.get("uri"), str))
    if unnamed:
        yield ctx.finding(
            "MCPP-SKL03",
            f"{unnamed} skill entr{'y has' if unnamed == 1 else 'ies have'} no `uri`.",
            location=_EXTENSION_LOCATION,
            key="no-uri",
        )
    for uri, entry in _entries(probe):
        problems = S.entry_problems(entry)
        if problems:
            yield ctx.finding(
                "MCPP-SKL03",
                f"{_location(uri)}: {len(problems)} problem(s) in the entry.",
                location=_location(uri),
                evidence=[Evidence(summary=visible(p)[:300]) for p in problems[:10]],
            )


@check(
    id="MCPP-SKL04",
    title="Skill content does not match its entry",
    severity=Severity.HIGH,
    revisions=_REVISIONS,
    references=[R.MCP_SKILLS_INTEGRITY],
    rationale="""Hosts MUST verify every file they read against the entry's `size` and
        SHA-256 `digest`, and MUST compare the SKILL.md frontmatter field by field with the
        entry's `frontmatter`; any discrepancy means the skill must not be loaded. A mismatch
        is either a broken publishing pipeline (the skill is unusable in conforming hosts) or
        content changed after the entry was built, which is what a rug pull or an
        intermediary rewriting content looks like.""",
    remediation="""Build entries from the exact bytes served (the SDK `skillEntry` helpers
        do), serve files byte for byte, and keep the frontmatter in the entry identical to
        the one in SKILL.md. If you did not change the skill, investigate the content path.""",
)
def skl04(ctx: ScanContext) -> Iterator[Finding]:
    probe = _probe(ctx)
    if probe is None:
        return
    files: dict[str, list[Any]] = {}
    for f in probe.files:
        files.setdefault(f.skill_uri, []).append(f)
    for uri, entry in _entries(probe):
        issues: list[str] = []
        manifest = {
            r["uri"]: r for r in S.resources_of(entry) or [] if isinstance(r.get("uri"), str)
        }
        for f in files.get(uri, []):
            path = S.relative_path(uri, f.uri)
            if f.error:
                if f.uri in manifest:
                    issues.append(f"{path}: listed in the manifest but not readable ({f.error})")
                continue
            if f.data is None:
                continue
            listed = manifest.get(f.uri)
            if listed is not None:
                size = listed.get("size")
                if isinstance(size, int) and size != len(f.data):
                    issues.append(f"{path}: {len(f.data)} bytes served, entry says {size}")
                want = listed.get("digest")
                got = S.digest(f.data)
                if isinstance(want, str) and want != got:
                    issues.append(f"{path}: digest {got[:19]}… served, entry says {want[:19]}…")
            if f.uri == uri and f.text is not None:
                fm, error = S.parse_frontmatter(f.text)
                if error:
                    issues.append(f"{path}: {error}")
                elif not S.json_equal(fm, thaw(entry.get("frontmatter"))):
                    issues.append(f"{path}: frontmatter differs from the entry's `frontmatter`")
        if issues:
            yield ctx.finding(
                "MCPP-SKL04",
                f"{_location(uri)}: served content does not match the entry; conforming hosts "
                "refuse to load it.",
                location=_location(uri),
                evidence=[Evidence(summary=visible(i)[:300]) for i in issues[:10]],
            )


@check(
    id="MCPP-SKL05",
    title="Skill published without content integrity (dynamic)",
    severity=Severity.LOW,
    revisions=_REVISIONS,
    references=[R.MCP_SKILLS, R.MCP_SKILLS_SECURITY],
    rationale="""A skill whose `resources` is `"dynamic"` carries no digests: hosts cannot
        verify what they read, an approval cannot be bound to content, and hosts MAY refuse
        to load it. A pinned baseline cannot detect changes in its files either.""",
    remediation="""Publish a manifest with digests whenever the content can be made stable;
        keep generated content in tool results rather than in skill files.""",
)
def skl05(ctx: ScanContext) -> Iterator[Finding]:
    probe = _probe(ctx)
    if probe is None:
        return
    for uri, entry in _entries(probe):
        if S.is_dynamic(entry):
            yield ctx.finding(
                "MCPP-SKL05",
                f"{_location(uri)} is dynamic: its content cannot be verified or pinned.",
                location=_location(uri),
            )


@check(
    id="MCPP-SKL06",
    title="Skill exceeds the SEP-2640 size limits",
    severity=Severity.LOW,
    revisions=_REVISIONS,
    references=[R.MCP_SKILLS],
    rationale=f"""Hosts only have to accept skills of up to {S.MAX_RESOURCES} files and
        {S.MAX_TOTAL_BYTES} bytes (16 MiB) in total; servers SHOULD NOT serve larger ones,
        which no conforming host is guaranteed to load. Oversized skills are also hard to
        review before approval.""",
    remediation="""Split the skill, or move large assets out of it.""",
)
def skl06(ctx: ScanContext) -> Iterator[Finding]:
    probe = _probe(ctx)
    if probe is None:
        return
    for uri, entry in _entries(probe):
        manifest = S.resources_of(entry)
        if manifest is None:
            continue
        total = sum(r["size"] for r in manifest if isinstance(r.get("size"), int))
        over = []
        if len(manifest) > S.MAX_RESOURCES:
            over.append(f"{len(manifest)} files (limit {S.MAX_RESOURCES})")
        if total > S.MAX_TOTAL_BYTES:
            over.append(f"{total} bytes (limit {S.MAX_TOTAL_BYTES})")
        if over:
            yield ctx.finding(
                "MCPP-SKL06",
                f"{_location(uri)}: {', '.join(over)}.",
                location=_location(uri),
            )


@check(
    id="MCPP-SKL07",
    title="Skill frontmatter requests host permissions",
    severity=Severity.MEDIUM,
    revisions=_REVISIONS,
    references=[R.MCP_SKILLS_SECURITY, R.AGENT_SKILLS],
    rationale="""A remote server populating `allowed-tools` (or hooks and similar fields) is
        asking for elevated access on the user's machine, not describing itself. SEP-2640
        requires hosts to ignore such fields for MCP-served skills unless the user approves
        that grant for that skill; hosts that do not follow it, or users who approve without
        reading, hand the server pre-approved tool use.""",
    remediation="""Remove permission fields from skills served over MCP; let the user grant
        tools in their own configuration. Review any skill that asks for shell or file
        access before approving it.""",
)
def skl07(ctx: ScanContext) -> Iterator[Finding]:
    probe = _probe(ctx)
    if probe is None:
        return
    for uri, entry in _entries(probe):
        fm = entry.get("frontmatter")
        if not isinstance(fm, Mapping):
            continue
        fields = [k for k in _PERMISSION_FIELDS if k in fm]
        if fields:
            yield ctx.finding(
                "MCPP-SKL07",
                f"{_location(uri)} requests host permissions through {', '.join(fields)}.",
                location=_location(uri),
                evidence=[
                    Evidence(summary=k, excerpt=visible(str(thaw(fm[k])))[:300]) for k in fields
                ],
            )


@check(
    id="MCPP-SKL08",
    title="Skill bundles code (inventory)",
    severity=Severity.INFO,
    revisions=_REVISIONS,
    references=[R.MCP_SKILLS_SECURITY],
    rationale="""An MCP-served skill can place server-authored code on the host and direct the
        model to run it; SEP-2640 calls skills a higher-risk surface than remote tool calls and
        forbids hosts to execute their code without explicit per-skill approval. The scanner
        does not judge code: this finding lists it (path, language, size, digest) so it can be
        reviewed before approval. Binaries cannot be reviewed at all.""",
    remediation="""Review every listed file before approving the skill. Prefer skills
        without executables; ship scripts as readable source, never as binaries.""",
)
def skl08(ctx: ScanContext) -> Iterator[Finding]:
    probe = _probe(ctx)
    if probe is None:
        return
    read = {f.uri: f for f in probe.files}
    for uri, entry in _entries(probe):
        rows: list[tuple[str, str, bool]] = []
        for r in S.resources_of(entry) or []:
            ruri = r.get("uri")
            if not isinstance(ruri, str) or ruri == uri:
                continue
            f = read.get(ruri)
            mime = f.mime_type if f else None
            if not S.is_code(ruri, mime):
                continue
            binary = S.is_binary_executable(ruri, mime, f.data if f else None)
            ext = S.extension_of(ruri)
            language = "binary" if binary else _LANGUAGES.get(ext, ext or mime or "unknown")
            size = r.get("size")
            dg = r.get("digest")
            rows.append(
                (
                    f"{S.relative_path(uri, ruri)} · {language} · "
                    f"{size if isinstance(size, int) else '?'} bytes · "
                    f"{dg[:19] + '…' if isinstance(dg, str) else 'no digest'}",
                    visible(ruri),
                    binary,
                )
            )
        if rows:
            binaries = sum(1 for _, _, b in rows if b)
            yield ctx.finding(
                "MCPP-SKL08",
                f"{_location(uri)} bundles {len(rows)} code file(s)"
                + (f", {binaries} of them binary (not reviewable)" if binaries else "")
                + ".",
                location=_location(uri),
                severity=Severity.LOW if binaries else Severity.INFO,
                evidence=[Evidence(summary=visible(row)[:300]) for row, _, _ in rows[:20]],
            )
