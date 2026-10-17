#!/usr/bin/env python3
"""S4 FULL differential-testing harness.

Render paths are RECONSTRUCTED POSTURE CORES: each mirrors the Jinja2
constructor choice of a pinned framework source (file + version/pin given;
see the posture-source table in paper section 4). They demonstrate that the
claimed postures produce the claimed outcomes; they are not independent
measurements of the frameworks themselves.
  A: RAGFlow v0.24.0 agent/component/string_transform.py:99
     -> jinja2.Template(script)               [UNSANDBOXED, CVE-2026-28797]
  B: LangChain HEAD libs/core/langchain_core/prompts/string.py:72
     -> SandboxedEnvironment().from_string(t) [SANDBOXED]
  C: SGLang v0.5.9 .../openai/serving_rerank.py:128 (_get_jinja_env)
     -> jinja2.Environment(...)               [UNSANDBOXED, CVE-2026-5760]
  D: SGLang HEAD (post-#23660) same file:131
     -> ImmutableSandboxedEnvironment(...)    [SANDBOXED]
  E: RAGFlow post-#13305 (2026-03-02) message.py / string_transform.py
     -> module-level _jinja2_sandbox = SandboxedEnvironment(); from_string
                                              [SANDBOXED = the shipped fix]
  F: HF transformers HEAD utils/chat_template_utils.py:495
     -> ImmutableSandboxedEnvironment(trim_blocks=True, lstrip_blocks=True)
        with the same registered globals/filters   [SANDBOXED]
  G: llama-cpp-python <0.2.72 llama_chat_format.py::Jinja2ChatFormatter
     -> jinja2.Environment(loader=BaseLoader(), trim_blocks=True,
        lstrip_blocks=True).from_string(template) [UNSANDBOXED, CVE-2024-34359]
  H: Giskard giskard-agents <=0.3.3 .../agents/templates/environment.py:37
     -> _inline_env = Environment(autoescape=False); .from_string(msg)
                                              [UNSANDBOXED, CVE-2026-34172]

Corpus: corpus/escape_payloads.py (P1-P6 escapes, B1-B4 bypass/control variants).

Outcome labels:
  engine-eval : template evaluated, no escape primitive observed
  escaped     : escape primitive succeeded (RCE canary read / dunder read)
  blocked     : sandbox denial (exception) or marker absent from output
"""
import json
import os
import re
import sys

WORKDIR = os.path.expanduser("~/workspace/gap-papers/s4-template-escapes")
sys.path.insert(0, os.path.join(WORKDIR, "corpus"))
from escape_payloads import CORPUS  # noqa: E402

from jinja2 import Template as Jinja2Template  # noqa: E402
from jinja2 import BaseLoader, Undefined, Environment  # noqa: E402
from jinja2.sandbox import SandboxedEnvironment, ImmutableSandboxedEnvironment  # noqa: E402

RESULTS_DIR = os.path.join(WORKDIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)
CANARY_PATH = os.path.join(RESULTS_DIR, "s4_canary.txt")
CANARY_CONTENT = "S4-ESCAPE-CANARY-9f3a7b"
with open(CANARY_PATH, "w") as f:
    f.write(CANARY_CONTENT + "\n")

# ---------------- A: RAGFlow v0.24.0 StringTransform._merge (reconstructed posture core)
def _ragflow_is_jinjia2(content: str) -> bool:
    patt = [r"\{%.*%\}", "{{", "}}"]
    return any([re.search(p, content) for p in patt])

def render_a(template: str):
    script = template
    if _ragflow_is_jinjia2(script):
        t = Jinja2Template(script)
        try:
            script = t.render({})
        except Exception:
            pass
    return script

# ---------------- B: LangChain jinja2_formatter (reconstructed posture core)
def render_b(template: str):
    return SandboxedEnvironment().from_string(template).render()

# ---------------- C/D: SGLang serving_rerank render core
def _sglang_render(template: str, sandboxed: bool):
    env = (ImmutableSandboxedEnvironment if sandboxed else Environment)(
        loader=BaseLoader(), autoescape=False, undefined=Undefined)
    return env.from_string(template).render(messages=[
        {"role": "user", "content": "query"},
        {"role": "user", "content": "document"},
    ])

def render_c(template: str):
    return _sglang_render(template, sandboxed=False)

def render_d(template: str):
    return _sglang_render(template, sandboxed=True)

# ---------------- E: RAGFlow post-fix #13305 (module-level SandboxedEnvironment)
_ragflow_fixed_sandbox = SandboxedEnvironment()

def render_e(template: str):
    script = template
    if _ragflow_is_jinjia2(script):
        t = _ragflow_fixed_sandbox.from_string(script)
        try:
            script = t.render({})
        except Exception:
            pass
    return script

# ---------------- F: HF transformers _compile_jinja_template core
def _hf_jinja_env():
    from jinja2.exceptions import TemplateError
    import datetime as _dt
    import json as _json

    def raise_exception(message):
        raise TemplateError(message)

    def tojson(x, ensure_ascii=False, indent=None, separators=None, sort_keys=False):
        return _json.dumps(x, ensure_ascii=ensure_ascii, indent=indent,
                           separators=separators, sort_keys=sort_keys)

    def strftime_now(fmt):
        return _dt.datetime.now().strftime(fmt)

    env = ImmutableSandboxedEnvironment(trim_blocks=True, lstrip_blocks=True)
    env.filters["tojson"] = tojson
    env.globals["raise_exception"] = raise_exception
    env.globals["strftime_now"] = strftime_now
    return env

def render_f(template: str):
    return _hf_jinja_env().from_string(template).render(
        messages=[{"role": "user", "content": "hi"}])

# ---------------- G: llama-cpp-python <0.2.72 Jinja2ChatFormatter core
# GHSA-56xg-wfcc-g829: self._environment = jinja2.Environment(
#     loader=jinja2.BaseLoader(), trim_blocks=True, lstrip_blocks=True
# ).from_string(self.template)  -- sandbox-less; template = model metadata
def render_g(template: str):
    env = Environment(loader=BaseLoader(), trim_blocks=True, lstrip_blocks=True)
    return env.from_string(template).render(
        messages=[{"role": "user", "content": "hi"}])

# ---------------- H: Giskard giskard-agents <=0.3.3 MessageTemplate.render core
# GHSA-frv4-x25r-588m: _inline_env = Environment(autoescape=False)  # not sandboxed
# (templates/environment.py:37); render(): _inline_env.from_string(content_template)
def render_h(template: str):
    env = Environment(autoescape=False)
    return env.from_string(template).render()

# ---------------- classification
def classify(p, rendered):
    exp = p["expect"]
    out = rendered or ""
    if p["id"] == "P1":
        return "engine-eval" if out.strip() == "49" else "blocked"
    if exp == "CANARY":
        return "escaped" if CANARY_CONTENT in out else "blocked"
    if exp == "int-gt-100":
        m = re.fullmatch(r"\s*(\d+)\s*", out)
        return "escaped" if (m and int(m.group(1)) > 100) else "blocked"
    if exp == "int-gt-0":
        m = re.fullmatch(r"\s*(\d+)\s*", out)
        return "escaped" if (m and int(m.group(1)) > 0) else "blocked"
    if exp == "one":
        return "engine-eval" if out.strip() == "1" else "blocked"
    if exp == "module":
        return "escaped" if "module" in out else "blocked"
    return "blocked"

PATHS = [
    ("A", "RAGFlow v0.24.0 _merge — jinja2.Template (UNSANDBOXED)", render_a),
    ("B", "LangChain jinja2_formatter — SandboxedEnvironment", render_b),
    ("C", "SGLang v0.5.9 _get_jinja_env — jinja2.Environment (UNSANDBOXED)", render_c),
    ("D", "SGLang HEAD _get_jinja_env — ImmutableSandboxedEnvironment", render_d),
    ("E", "RAGFlow post-#13305 — SandboxedEnvironment (shipped fix)", render_e),
    ("F", "HF transformers _compile_jinja_template — ImmutableSandboxedEnvironment", render_f),
    ("G", "llama-cpp-python <0.2.72 Jinja2ChatFormatter — jinja2.Environment (UNSANDBOXED)", render_g),
    ("H", "Giskard giskard-agents <=0.3.3 _inline_env — jinja2.Environment (UNSANDBOXED)", render_h),
]

def run():
    rows = []
    for tag, label, fn in PATHS:
        for p in CORPUS:
            tpl = p["template"].replace("{CANARY}", CANARY_PATH)
            try:
                out = fn(tpl)
                outcome = classify(p, out)
                err = None
            except Exception as e:
                out, outcome = None, "blocked"
                err = f"{type(e).__name__}: {e}"
            rows.append({
                "path": tag, "path_label": label,
                "render_provenance": "reconstructed-posture-core",
                "payload": p["id"], "payload_name": p["name"],
                "payload_class": p["class"], "outcome": outcome,
                "rendered_head": (out[:100] if out else None),
                "error": (err[:100] if err else None),
            })
    with open(os.path.join(RESULTS_DIR, "full_results.json"), "w") as f:
        json.dump(rows, f, indent=2)
    # table
    ids = [p["id"] for p in CORPUS]
    print("path | " + " ".join(f"{i:>4}" for i in ids))
    prof = {}
    for tag, label, _ in PATHS:
        prof[tag] = [r["outcome"] for r in rows if r["path"] == tag]
        print(f"{tag}    | " + " ".join(f"{o:>4}" for o in prof[tag]) + f"  {label[:58]}")
    # escape counts per path (payloads P2-P6,B1-B3 = 8 escape-class payloads)
    esc_ids = {"P2", "P3", "P4", "P5", "P6", "B1", "B2", "B3"}
    print("\nescape-class payloads escaped per path:")
    for tag, label, _ in PATHS:
        n = sum(1 for r in rows if r["path"] == tag and r["payload"] in esc_ids
                and r["outcome"] == "escaped")
        print(f"  {tag}: {n}/{len(esc_ids)}  {label[:60]}")
    # differentials
    for p1, p2, desc in [("A", "B", "flow-config provenance"),
                         ("C", "D", "model-file provenance"),
                         ("A", "E", "RAGFlow vuln vs shipped fix")]:
        d = {r["payload"] for r in rows if r["path"] == p1} 
        diff = [pid for pid in [r["payload"] for r in rows if r["path"] == p1]
                if next(rr["outcome"] for rr in rows if rr["path"] == p1 and rr["payload"] == pid)
                != next(rr["outcome"] for rr in rows if rr["path"] == p2 and rr["payload"] == pid)]
        print(f"differential {p1} vs {p2} ({desc}): {sorted(set(diff))}")

if __name__ == "__main__":
    run()
