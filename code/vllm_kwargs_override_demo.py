#!/usr/bin/env python3
"""S4 — vLLM CVE-2025-61620 template-override logic demonstration.

This is a LOGIC-LEVEL reproduction (not a live vLLM import; vllm requires
torch/GPU deps). It replays the exact kwargs-merging behavior documented in:

  VULNERABLE (pre-fix), per CERT/CC message archives-cert.univ-amu.fr/2025/
  certmsgVULN673 quoting vllm/entrypoints/openai/serving_engine.py L794-816:
      _chat_template_kwargs: dict[str, Any] = dict(
          chat_template=chat_template, add_generation_prompt=..., ...)
      _chat_template_kwargs.update(chat_template_kwargs or {})
      request_prompt = apply_hf_chat_template(..., **_chat_template_kwargs)

  FIXED (HEAD), vllm/renderers/hf.py::resolve_chat_template_kwargs:
      unexpected_vars = {"chat_template", "tokenize"}
      if raise_on_unexpected and (unexpected_vars & chat_template_kwargs.keys()):
          raise ValueError("Found unexpected chat template kwargs from request: ...")

Question tested: can an API client smuggle a `chat_template` key inside
`chat_template_kwargs` and thereby replace the template that gets rendered?
"""
import json, os

# Package-local results dir: <package>/results. (Path adapted from the
# research-workspace absolute path for a portable reproduction package;
# all replay logic below is unchanged.)
RESULTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
os.makedirs(RESULTS, exist_ok=True)

SERVER_TEMPLATE = "{% for m in messages %}{{ m.content }}{% endfor %}"
ATTACKER_TEMPLATE = "{% for x in range(10**9) %}{{ x }}{% endfor %}"  # resource-exhaustion shape

# client-supplied request fields (attacker controlled)
chat_template = None                      # top-level param: not supplied
chat_template_kwargs = {"chat_template": ATTACKER_TEMPLATE}  # smuggled key

# ---- vulnerable merge (pre-fix, verbatim logic from the CERT-quoted code)
_vuln = dict(chat_template=chat_template or SERVER_TEMPLATE,
             add_generation_prompt=True)
_vuln.update(chat_template_kwargs or {})
vuln_resolved_template = _vuln["chat_template"]

# ---- fixed merge (HEAD logic: reject unexpected keys)
def resolve_fixed(chat_template_kwargs):
    unexpected_vars = {"chat_template", "tokenize"}
    if unexpected_vars & set((chat_template_kwargs or {}).keys()):
        raise ValueError("Found unexpected chat template kwargs from request: "
                         f"{unexpected_vars & set(chat_template_kwargs.keys())}")
    return {k: v for k, v in (chat_template_kwargs or {}).items()
            if k not in unexpected_vars}

try:
    resolve_fixed(chat_template_kwargs)
    fixed_outcome = "NOT-BLOCKED (unexpected)"
except ValueError as e:
    fixed_outcome = f"BLOCKED: {e}"

rows = {
    "vulnerable_merge_resolved_template_is_attacker_controlled":
        vuln_resolved_template == ATTACKER_TEMPLATE,
    "vulnerable_merge_resolved_template_head": vuln_resolved_template[:60],
    "fixed_merge_outcome": fixed_outcome,
}
print(json.dumps(rows, indent=2))
with open(os.path.join(RESULTS, "vllm_kwargs_override_demo.json"), "w") as f:
    json.dump(rows, f, indent=2)
assert rows["vulnerable_merge_resolved_template_is_attacker_controlled"]
assert fixed_outcome.startswith("BLOCKED")
print("DEMO OK: old merge lets the client replace the template; "
      "fixed resolve_chat_template_kwargs rejects the smuggled key.")
