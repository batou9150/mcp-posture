# Changelog

## [1.1.2](https://github.com/batou9150/mcp-posture/compare/v1.1.1...v1.1.2) (2026-10-26)


### Bug Fixes

* **action:** run from the action's uv.lock and pin examples to the release ([7648695](https://github.com/batou9150/mcp-posture/commit/764869572cb69ed9e1fd717c00e4ceca3202e391))
* **engine:** keep IPv6 brackets in the plain-HTTP probe URL ([02c8899](https://github.com/batou9150/mcp-posture/commit/02c8899060ba4759b86b967eb00a4da71f77ac1f))
* **net:** never inflate compressed bodies past the size cap ([62ca691](https://github.com/batou9150/mcp-posture/commit/62ca691012d860726b09710a98e7dcc704134ab1))
* **pin:** compare every definition of a duplicated tool name ([507e3a3](https://github.com/batou9150/mcp-posture/commit/507e3a3b7a65bafd5e4df690674f5e4c875318f2))
* **tool01:** detect French instruction-like phrases ([77689ca](https://github.com/batou9150/mcp-posture/commit/77689cae338af785fdf06f11f20786e059a7e6e8))


### Dependencies

* bump certifi and opentelemetry-api for PYSEC-2026-4320 and CVE-2026-114603 ([b88b465](https://github.com/batou9150/mcp-posture/commit/b88b465e427fc8e93c3c46a99e1be72d9f7c6f0e))
* bump distroless/python3-debian13 from `774595d` to `83aa8d4` ([#4](https://github.com/batou9150/mcp-posture/issues/4)) ([1c7a5e2](https://github.com/batou9150/mcp-posture/commit/1c7a5e2e2af9fc5bac42c24b57c42b0c90689608))
* bump distroless/python3-debian13 from `83aa8d4` to `64e54c4` ([#11](https://github.com/batou9150/mcp-posture/issues/11)) ([14e861e](https://github.com/batou9150/mcp-posture/commit/14e861e8a0ea1f0bb65ecb820812d84aa0bf63fd))
* bump pydantic ([#12](https://github.com/batou9150/mcp-posture/issues/12)) ([6f3de2e](https://github.com/batou9150/mcp-posture/commit/6f3de2e3aa2d08bdede875ba03f9532247e6a443))
* bump the dev group across 1 directory with 2 updates ([#13](https://github.com/batou9150/mcp-posture/issues/13)) ([41bf62b](https://github.com/batou9150/mcp-posture/commit/41bf62b78f8bc882f0ee79246551e6a47a6d83f6))
* bump the dev group with 3 updates ([#6](https://github.com/batou9150/mcp-posture/issues/6)) ([48b1e8a](https://github.com/batou9150/mcp-posture/commit/48b1e8a323dc8c4e5633e6d0e0af7cfe303a5a4c))
* bump the runtime group with 2 updates ([#7](https://github.com/batou9150/mcp-posture/issues/7)) ([b87b175](https://github.com/batou9150/mcp-posture/commit/b87b1757afe2f2c250660203e1f1fcdb5af25f98))


### Documentation

* list every request a passive scan sends; correct the SSE cap ([20e6528](https://github.com/batou9150/mcp-posture/commit/20e652882a443ee67a5f60a5e4f7db2ff7e36518))

## [1.1.1](https://github.com/batou9150/mcp-posture/compare/v1.1.0...v1.1.1) (2026-10-05)


### Bug Fixes

* **tool01:** "silently" alone is API prose; flag it only next to an action on data ([0ea978f](https://github.com/batou9150/mcp-posture/commit/0ea978f23fd50ca02f6a98662df11f840bf24fc2))

## [1.1.0](https://github.com/batou9150/mcp-posture/compare/v1.0.0...v1.1.0) (2026-10-05)


### Features

* **login:** default client metadata document, advertised DCR grant types, always show the URL ([0538191](https://github.com/batou9150/mcp-posture/commit/0538191bb6bf30474a1452b7eeba654489e95226))
* mcp-posture login and scan --login (OAuth code flow + PKCE to your own server) ([96417bd](https://github.com/batou9150/mcp-posture/commit/96417bd5bffa6a545fe8d2b670251ba4509e7064))


### Bug Fixes

* **login:** do not report Google's long-form email/profile scopes as missing ([66a4ced](https://github.com/batou9150/mcp-posture/commit/66a4ced90cbf6f04493b7df0002f64939a181a68))
* **login:** tell how to reuse a client that cannot be deleted (client ID and port) ([3dc59f5](https://github.com/batou9150/mcp-posture/commit/3dc59f5bd0a018440cbd8a8f47b4fecae0f4f092))

## [1.0.0](https://github.com/batou9150/mcp-posture/compare/v1.0.0-rc1...v1.0.0) (2026-10-05)


### Documentation

* install from PyPI and GHCR ([5d18acc](https://github.com/batou9150/mcp-posture/commit/5d18accb1de2f538ab302d19b91a396ffc26d954))

## [1.0.0-rc1](https://github.com/batou9150/mcp-posture/releases/tag/v1.0.0-rc1) (2026-10-05)

First release candidate.

### Features

* Passive scanner for remote MCP servers (Streamable HTTP, legacy HTTP+SSE detection), aware of
  MCP revisions 2025-03-26, 2025-06-18, 2025-11-25 and 2026-07-28.
* Checks: transport (TRN01-11), authentication challenge (AUTHN01-06), Protected Resource
  Metadata (PRM01-11), authorization server metadata (ASM01-13), Client ID Metadata Documents
  (CIMD01-02), scopes (SCP01, SCP02, SCP04), tool surface (TOOL01-10), rug-pull pinning
  (PIN01-04).
* `mcp-posture cimd lint` for your own client's metadata document (CIMD50-57).
* Reports: table, JSON (versioned schema), SARIF 2.1.0 anchored to the declaring file,
  Markdown; suppressions with justification and expiry; `mcp-posture.toml`; targets from MCP
  client configs.
* Hardened HTTP layer: connect-time SSRF guard (IPv6 forms embedding IPv4 included, also
  enforced with `--proxy`), manual redirects without cross-origin credentials, capped bodies,
  a deadline on response headers and a per-target time limit (`--target-timeout`), token
  redaction that also masks truncated fragments, bounded JSON nesting.
* Reports neutralize server-controlled text: no control, bidi or invisible characters in any
  format, and no links, images, mentions or fence breaks in the Markdown summary.
* GitHub Action, distroless container image, Claude Code skill, documentation site.
