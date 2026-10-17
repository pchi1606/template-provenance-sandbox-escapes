# Reproduction package — "Template Provenance: Prompt-Template Sandbox Escapes as a Systematic Weakness Class Across Agent Frameworks"

Author: Prabhu Rangaraju (Independent Researcher).
Manuscript prepared for submission to the USENIX Conference on Secure
Agentic-AI Systems (SAIS '27).

## What this reproduces

The paper's headline measurement: a differential-testing harness replays a
corpus of 10 documented Jinja2 escape/sandbox-bypass payloads through
reconstructed render-posture cores mirroring the Jinja2 constructor choices
of eight pinned framework render paths (80 render cells), plus a
logic-level replay of vLLM's kwargs-override template-selection vector
(CVE-2025-61620). The framework-to-posture mapping is documented with
pinned source lines in POSTURE_SOURCES.md; the cores demonstrate that the
claimed postures produce the claimed outcomes rather than independently
measuring the frameworks.

Headline numbers the verifier checks:

- Unsandboxed paths (A: RAGFlow v0.24.0, C: SGLang v0.5.9,
  G: llama-cpp-python <0.2.72, H: Giskard giskard-agents <=0.3.3): all 8
  escape-class payloads execute — 8/8 escaped.
- Sandboxed paths (B: LangChain, D: SGLang fixed, E: RAGFlow fixed,
  F: HF transformers): 0/8 escaped — every malicious payload blocked.
- P1 (engine detection) and B4 (benign control) evaluate on all eight paths.
- vLLM: the pre-fix `dict.update` merge resolves the attacker-smuggled
  template; the fixed `resolve_chat_template_kwargs` rejects the key.

## Quick start

```bash
bash reproduce.sh
```

That installs `jinja2` if missing, runs the 80-cell harness and the vLLM
replay (CPU-only, a few seconds), then verifies every headline number and
confirms the fresh outputs match the committed expected outputs in
`results/expected/`. It exits nonzero on any mismatch.

## Layout

- `code/full_harness.py` — the 80-cell differential-testing harness
  (reconstructed render-posture cores for paths A–H).
- `code/sweep_scan.py` — the responsible-disclosure sweep scanner (AST scan
  over pinned framework clones; see paper Appendix A).
- `POSTURE_SOURCES.md` — framework-to-posture mapping: pinned file, version,
  and constructor line per path, with permalinked URLs.
- `code/pilot_harness.py` — the earlier pilot harness, kept for
  completeness (it needs the cloned framework source trees, so
  `reproduce.sh` does not run it).
- `code/vllm_kwargs_override_demo.py` — logic-level replay of the vLLM
  kwargs-override selection primitive.
- `corpus/escape_payloads.py` — the 10-payload corpus (P1–P6 escapes,
  B1–B4 bypass/control variants) with sources.
- `results/expected/` — committed expected outputs the verifier compares
  against.
- `scripts/verify_reproduction.py` — the headline-number verifier.
- `DISCLOSURE_LOG.md` — responsible-disclosure log: no new live
  vulnerabilities were found, so no vendor disclosure was required.

## Requirements

Python 3.10+ and `jinja2` (installed automatically by `reproduce.sh`).
No API keys, no network access beyond the one-time `jinja2` install, no
GPU. All payloads are non-destructive read-only canaries; all vulnerable
versions exercised are historical, publicly documented, and patched.
