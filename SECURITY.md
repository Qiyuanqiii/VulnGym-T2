# Security Policy

## What this repository is

This repository contains **T2**, an offline-first workbench that turns a public
security advisory and a Git repository into structured, reviewable annotation
records (a VulnGym `entries.jsonl` candidate plus per-field evidence). It is a
data-labeling and research tool, not an exploitation framework.

The generated records describe where a vulnerability is located in source code
that is already public, together with the evidence the model read. Entries are
machine-produced, carry `verify=0`, and are explicitly not human-confirmed
findings. See [README.md](README.md) for the boundaries this tool documents.

## Boundaries the code enforces

- Target repositories are read as Git objects only. Nothing is checked out,
  installed, or executed, and target project dependencies are never run.
- The model can only request seven read-only tools with fixed output caps; it
  cannot invoke arbitrary functions. Subprocess calls are argv-only, never
  through a shell, and each has a timeout.
- The bundled web workbench listens on `127.0.0.1` only, requires a same-origin
  request plus a per-session token, and caps request bodies.
- Model API keys are never written to outputs, logs, or the request ledger. They
  reach the child process over stdin at the moment a batch is confirmed.
- Network egress is limited to two purposes: public advisory fetches to the
  GitHub and OSV public endpoints, and model requests to `api.deepseek.com`.
  There is no automatic retry, provider switching, or source rotation on
  refusal or rate limiting.
- Nothing in this repository performs vulnerability scanning or active testing
  against running systems, and it is not intended for that use.

## Affiliation

This is an independent implementation. It is **not** a Tencent product and does
not carry Tencent's endorsement. Upstream VulnGym attribution and the icon
provenance are recorded in [vulngym_t2/web_assets/brand/README.md](vulngym_t2/web_assets/brand/README.md)
and [LICENSE](LICENSE).

## Reporting a concern

**Questions or concerns about the content of this repository** — please
[open an issue](https://github.com/Qiyuanqiii/VulnGym-T2/issues/new/choose) on
this repository. That is the fastest route and is preferred over filing a
platform abuse report; a maintainer reads it directly.

**A vulnerability in this tool itself** — for example anything involving API key
handling, the local web server, path or archive handling, or resource limits,
please use GitHub's *Report a vulnerability* form on the Security tab if it is
enabled for this repository. If it is not available, open a blank issue with the
word `security` in the title and describe only what is needed to locate the
problem; do not post reproduction details in public.

## Scope

Requests to remove, restrict, or re-license upstream public advisory text or
third-party Git history that this tool only reads are out of scope here; those
belong to the original sources. Requests about files this repository distributes
are in scope and will be handled through the issue tracker above.
