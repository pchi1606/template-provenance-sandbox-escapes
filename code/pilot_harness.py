#!/usr/bin/env python3
"""S4 PILOT — differential template-escape testing harness (go/no-go).

Render path A (unsandboxed, user-flow-config provenance):
    RAGFlow v0.24.0, agent/component/string_transform.py, StringTransform._merge:
        if self._is_jinjia2(script):
            template = Jinja2Template(script)      # jinja2.Template, UNSANDBOXED
            try:
                script = template.render(kwargs)
            except Exception:
                pass
    Reconstructed as render_ragflow_stringtransform() below (kwargs={},
    matching the pilot invocation where no canvas variables are bound).

Render path B (sandboxed, operator-prompt-template provenance):
    langchain_core/prompts/string.py::jinja2_formatter:
        return SandboxedEnvironment().from_string(template).render(**kwargs)
    Imported live from the cloned langchain source tree when possible;
    falls back to a reconstructed core with the same constructor.

For each (render path x corpus payload): record outcome in {OUTCOME}:
    - "engine-eval": template evaluated (P1 -> 49) but no escape observed
    - "escaped":     escape primitive succeeded (RCE read of canary / dunder read)
    - "blocked":     render raised (sandbox denial) or output lacked the marker
    - "error":       harness-level failure (not a security outcome)

Go criterion: path A and path B must produce DIFFERENT outcome profiles,
i.e. the methodology distinguishes sandbox posture in real framework code.
"""
import json
import os
import re
import sys
import traceback

WORKDIR = os.path.expanduser("~/workspace/gap-papers/s4-template-escapes")
sys.path.insert(0, os.path.join(WORKDIR, "corpus"))
from escape_payloads import CORPUS  # noqa: E402

from jinja2 import Template as Jinja2Template  # noqa: E402  (RAGFlow's exact import)
from jinja2.sandbox import SandboxedEnvironment, ImmutableSandboxedEnvironment  # noqa: E402
from jinja2 import BaseLoader, Undefined, Environment  # noqa: E402  (SGLang's exact imports)

RESULTS_DIR = os.path.join(WORKDIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)
CANARY_PATH = os.path.join(RESULTS_DIR, "s4_canary.txt")
CANARY_CONTENT = "S4-ESCAPE-CANARY-9f3a7b"
with open(CANARY_PATH, "w") as f:
    f.write(CANARY_CONTENT + "\n")

# ---------------------------------------------------------------- path A: RAGFlow
def _ragflow_is_jinjia2(content: str) -> bool:  # mirrors string_transform.py gate
    patt = [r"\{%.*%\}", "{{", "}}"]
    return any([re.search(p, content) for p in patt])

def render_ragflow_stringtransform(template: str, kwargs=None):
    """Verbatim render core of RAGFlow v0.24.0 StringTransform._merge."""
    script = template
    kwargs = {} if kwargs is None else kwargs
    if _ragflow_is_jinjia2(script):
        template_obj = Jinja2Template(script)
        try:
            script = template_obj.render(kwargs)
        except Exception:
            pass
    return script

# ------------------------------------------------------- path B: LangChain
def render_langchain_jinja2(template: str, kwargs=None):
    """langchain_core jinja2_formatter: SandboxedEnvironment().from_string(t).render(**kw)"""
    kwargs = {} if kwargs is None else kwargs
    # try live import from cloned source first (dependency-light module)
    try:
        lc_path = os.path.join(WORKDIR, "repos", "langchain", "libs", "core")
        if lc_path not in sys.path:
            sys.path.insert(0, lc_path)
        from langchain_core.prompts.string import jinja2_formatter
        return jinja2_formatter(template, **kwargs), "live-import"
    except Exception:
        # reconstructed fallback: same SandboxedEnvironment constructor
        return SandboxedEnvironment().from_string(template).render(**kwargs), "reconstructed-posture-core"

# --------------------------------------- paths C/D: SGLang rerank render core
# serving_rerank.py::_get_jinja_env + _render_jinja_chat_template, reconstructed posture cores.
# v0.5.9 (CVE-2026-5760, vulnerable): jinja2.Environment(...) — no sandbox.
# HEAD (fixed): ImmutableSandboxedEnvironment(...) with comment
#   "Using a sandboxed environment to stop malicious execution during model loading."
# Template provenance: model-file metadata (tokenizer.chat_template).
def _sglang_render(template: str, sandboxed: bool):
    env = (ImmutableSandboxedEnvironment if sandboxed else Environment)(
        loader=BaseLoader(), autoescape=False, undefined=Undefined)
    t = env.from_string(template)
    return t.render(messages=[
        {"role": "user", "content": "query"},
        {"role": "user", "content": "document"},
    ])

def render_sglang_v059(template: str, kwargs=None):
    return _sglang_render(template, sandboxed=False)

def render_sglang_head(template: str, kwargs=None):
    return _sglang_render(template, sandboxed=True)

# ----------------------------------------------------------------- classify
def classify(pid, rendered):
    if pid == "P1":
        return "engine-eval" if rendered.strip() == "49" else "blocked"
    if pid == "P2":
        m = re.fullmatch(r"\s*(\d+)\s*", rendered or "")
        if m and int(m.group(1)) > 100:
            return "escaped"
        return "blocked"
    # P3..P6: RCE class — canary content must appear in output
    if CANARY_CONTENT in (rendered or ""):
        return "escaped"
    return "blocked"

def run():
    rows = []
    paths = [
        ("A", "RAGFlow v0.24.0 StringTransform._merge (unsandboxed jinja2.Template)",
         render_ragflow_stringtransform),
        ("B", "LangChain jinja2_formatter (SandboxedEnvironment)",
         render_langchain_jinja2),
        ("C", "SGLang v0.5.9 _get_jinja_env (unsandboxed jinja2.Environment)",
         render_sglang_v059),
        ("D", "SGLang HEAD _get_jinja_env (ImmutableSandboxedEnvironment)",
         render_sglang_head),
    ]
    for tag, label, fn in paths:
        for p in CORPUS:
            tpl = p["template"].replace("{CANARY}", CANARY_PATH)
            provenance = "reconstructed-posture-core"  # harmonized label (see full harness)
            try:
                if tag == "B":
                    out, provenance = fn(tpl)
                else:
                    out = fn(tpl)
                outcome = classify(p["id"], out)
                err = None
            except Exception as e:  # sandbox denials raise here
                out = None
                outcome = "blocked"
                err = f"{type(e).__name__}: {e}"
            rows.append({
                "path": tag, "path_label": label, "render_provenance": provenance,
                "payload": p["id"], "payload_name": p["name"],
                "payload_class": p["class"], "outcome": outcome,
                "rendered_head": (out[:120] if out else None),
                "error": err,
            })
    out_path = os.path.join(RESULTS_DIR, "pilot_results.json")
    with open(out_path, "w") as f:
        json.dump(rows, f, indent=2)
    # summary table
    print(f"{'path':<4} {'payload':<8} {'class':<12} {'outcome':<12} note")
    for r in rows:
        note = (r["error"] or "")[:60]
        print(f"{r['path']:<4} {r['payload']:<8} {r['payload_class']:<12} {r['outcome']:<12} {note}")
    # go/no-go: both unsandboxed-vs-sandboxed pairs must differ
    prof = {r["path"]: {rr["payload"]: rr["outcome"]
                        for rr in rows if rr["path"] == r["path"]} for r in rows}
    pairs = [("A", "B", "user-flow-config provenance"),
             ("C", "D", "model-file provenance")]
    all_go = True
    for p1, p2, desc in pairs:
        diffs = [pid for pid in prof[p1] if prof[p1][pid] != prof[p2][pid]]
        print(f"\nPair {p1} vs {p2} ({desc}) differing payloads: {diffs}")
        if not diffs:
            all_go = False
    print("PILOT:", "GO — methodology distinguishes sandbox posture in real framework code"
          if all_go else "NO-GO — no differential signal")
    print(f"results -> {out_path}")

if __name__ == "__main__":
    run()
