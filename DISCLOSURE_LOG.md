# Responsible Disclosure Log — TRACK S4 (prompt-template sandbox escapes)

## Clock
- **Project outset / disclosure clock started:** 2026-10-04
- **Testing method:** local-only differential testing against pinned historical
  source versions and current HEAD. No live systems, no production endpoints,
  no third-party exploit PoCs used. All RCE-class payloads are non-destructive
  (read-only read of a local canary file; no writes, no exfiltration).

## Findings vs. current code (all checked 2026-10-04)
| Framework / component | Current state | New live flaw? |
|---|---|---|
| RAGFlow agent (HEAD) | Python agent removed 2026-09-28 (#20289); Go rewrite has no Jinja2 render surface | No |
| SGLang serving_rerank.py (HEAD) | ImmutableSandboxedEnvironment since #23660 (2026-04-29) | No |
| SGLang other serving paths (chat/decisions/embedding) | delegate to HF transformers apply_chat_template (sandboxed) | No |
| LangChain jinja2_formatter (HEAD) | SandboxedEnvironment | No |
| LangGraph (HEAD) | no Jinja2 usage in libs/ | No (no surface) |
| vLLM renderers/hf.py (HEAD) | resolve_chat_template_kwargs rejects smuggled keys; safe_apply_chat_template | No |
| HF transformers chat_template_utils (HEAD) | ImmutableSandboxedEnvironment | No |

## Conclusion
**No new live vulnerabilities found.** All tested current code is either
sandboxed, fixed, or has no template-render surface. The vulnerable versions
exercised (RAGFlow v0.24.0, SGLang v0.5.9) correspond to already-published
CVEs with vendor patches available.

**No vendor disclosure was required** (nothing new to disclose). If any future
testing under this track surfaces a live flaw, disclosure to the affected
vendor will begin before any publication, and this log will be updated with
dates, contacts, and response status.

## Ethics note (for the manuscript appendix)
- Only historical, already-disclosed vulnerable versions were executed.
- Payloads are documented, non-destructive, and executed in an isolated VM.
- No credentials, no PII, and no production infrastructure were involved.
- Findings about fixed code are reported as fix-verification, not as new flaws.
