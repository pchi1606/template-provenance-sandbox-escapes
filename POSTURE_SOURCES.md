# S4 Posture Sources — framework → sandbox-posture mapping

Each render-posture core in `code/full_harness.py` (paths A–H) mirrors the
Jinja2 constructor choice of a pinned framework source. This file records the
exact file, version/pin, and constructor line each core mirrors, with
permalinked URLs verified 2026-10-09. The cores are reconstructions
demonstrating that the claimed postures produce the claimed outcomes; they
are not independent measurements of the frameworks.

| Path | Framework @ pin | Constructor choice (file:line) | Permalink |
|---|---|---|---|
| A | RAGFlow v0.24.0 | `agent/component/string_transform.py:99` — `template = Jinja2Template(script)` (`from jinja2 import Template as Jinja2Template`, line 21); `message.py:191` same idiom | https://github.com/infiniflow/ragflow/blob/v0.24.0/agent/component/string_transform.py#L99 (also: GHSA-vvwj-fvwh-4whx) |
| B | LangChain HEAD (commit 007cc15, 2026-10-04) | `libs/core/langchain_core/prompts/string.py:72` — `return SandboxedEnvironment().from_string(template).render(**kwargs)` | local clone `repos/langchain` @ 007cc15 |
| C | SGLang v0.5.9 | `python/sglang/srt/entrypoints/openai/serving_rerank.py:128` — `return jinja2.Environment(loader=jinja2.BaseLoader(), autoescape=False, undefined=jinja2.Undefined)` | https://github.com/sgl-project/sglang/blob/v0.5.9/python/sglang/srt/entrypoints/openai/serving_rerank.py#L128 |
| D | SGLang HEAD (commit f385390, 2026-10-05; post-#23660) | same file `:131` — `return ImmutableSandboxedEnvironment(` | https://github.com/sgl-project/sglang/blob/f385390be593575cda74cda06bc3a82591d52b18/python/sglang/srt/entrypoints/openai/serving_rerank.py#L131 |
| E | RAGFlow post-#13305 (merged 2026-03-02) | `agent/component/message.py` and `agent/component/string_transform.py` — module-level `_jinja2_sandbox = SandboxedEnvironment()`; `_jinja2_sandbox.from_string(...)` replaces `Jinja2Template(...)` (+8/−4 diff) | https://github.com/infiniflow/ragflow/pull/13305/files |
| F | HF transformers HEAD (verified at commit 541cf67a, 2026-09-30) | `src/transformers/utils/chat_template_utils.py:495` — `jinja_env = ImmutableSandboxedEnvironment(trim_blocks=True, lstrip_blocks=True, extensions=[...])` | https://github.com/huggingface/transformers/blob/541cf67a/src/transformers/utils/chat_template_utils.py#L495 |
| G | llama-cpp-python <0.2.72 | `llama_chat_format.py::Jinja2ChatFormatter.__init__` — `self._environment = jinja2.Environment(loader=jinja2.BaseLoader(), trim_blocks=True, lstrip_blocks=True).from_string(self.template)` (no sandbox) | https://github.com/advisories/GHSA-56xg-wfcc-g829 (source-to-sink section) |
| H | Giskard giskard-agents ≤0.3.3 | `libs/giskard-agents/src/giskard/agents/templates/environment.py:37` — `_inline_env = Environment(autoescape=False)` ("Not SandboxedEnvironment"); consumed by `MessageTemplate.render()` (`templates/message.py:33`: `_inline_env.from_string(self.content_template)`) | https://github.com/advisories/GHSA-frv4-x25r-588m (root-cause section) |

## Version-history PRs (merge-verified via GitHub API, 2026-10-09)

- RAGFlow #13305 "security: Adopt Jinja2 SandboxedEnvironment for template rendering." — merged 2026-03-02, +8/−4 — https://github.com/infiniflow/ragflow/pull/13305
- SGLang #16403 "feat: support qwen3(-VL) rerank scoring&chat template" — merged 2026-01-14, +1435/−34 — https://github.com/sgl-project/sglang/pull/16403
- SGLang #23660 "Fix for CVE-2026-5760" — merged 2026-04-29, +3/−2 — https://github.com/sgl-project/sglang/pull/23660
- RAGFlow #20289 "refactor: remove python source code, part2" — merged 2026-09-28, +0/−205285 — https://github.com/infiniflow/ragflow/pull/20289
- vLLM #25794 "Add filtering for chat template kwargs" — merged 2025-09-27, +158/−6 — https://github.com/vllm-project/vllm/pull/25794
- HF transformers #30621 "Chat Template support for function calling and RAG" — merged 2024-06-11, +1164/−3 — https://github.com/huggingface/transformers/pull/30621

## HF sandbox-earliness evidence (#21 in review)

- `tokenization_utils_base.py` at commit `8b46c5bc` (2023-10-04) already contains `ImmutableSandboxedEnvironment` (2 occurrences) alongside `apply_chat_template` — the safe default predates the dedicated module.
- `chat_template_utils.py` created by #30621 (commit `edc1dffd`, 2024-06-11) with JSON-schema helpers only; `ImmutableSandboxedEnvironment` first appears in that file at commit `371b9c14` (2024-08-23).
