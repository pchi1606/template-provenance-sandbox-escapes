#!/usr/bin/env python3
"""Verify the S4 reproduction package: headline numbers from fresh outputs.

Run after the harnesses (via reproduce.sh). Every check below must pass;
any failure exits nonzero with a diagnostic message.

Headline checks (from the paper's Measurement Results):
  1. results/full_results.json holds exactly 80 rows (8 paths x 10 payloads),
     with no missing or partial entries.
  2. Escape-class payloads (P2-P6, B1-B3): unsandboxed paths A, C, G, H
     escaped 8/8; sandboxed paths B, D, E, F escaped 0/8 (all blocked).
  3. Controls: P1 (engine detection) and B4 (benign control) are engine-eval
     on all eight paths.
  4. results/vllm_kwargs_override_demo.json: the pre-fix dict.update merge
     resolves the attacker-controlled template, and the fixed
     resolve_chat_template_kwargs logic blocks the smuggled key.
  5. Fresh outputs match the committed expected outputs in results/expected/
     (semantic fields; rendered_head is diagnostic-only since it embeds the
     local canary path and a live subclass count, with a positive control
     that RCE escapes exfiltrated the canary content).
"""

import json
import os
import sys

PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(PKG, "results")
EXPECTED = os.path.join(RESULTS, "expected")

ESCAPE_CLASS = ["P2", "P3", "P4", "P5", "P6", "B1", "B2", "B3"]
UNSANDBOXED = ["A", "C", "G", "H"]  # raw jinja2.Template / jinja2.Environment
SANDBOXED = ["B", "D", "E", "F"]  # SandboxedEnvironment / ImmutableSandboxedEnvironment


def fail(message):
    """Report a failed check and exit nonzero."""
    print("FAIL:", message)
    sys.exit(1)


def check(name, condition, detail=""):
    """Print a PASS line or fail with a diagnostic."""
    if not condition:
        fail("%s -- %s" % (name, detail))
    print("PASS:", name)


def main():
    # --- Check 1: output completeness (80 rows, 8 paths x 10 payloads) ---
    full_path = os.path.join(RESULTS, "full_results.json")
    if not os.path.exists(full_path):
        fail("full_results.json missing; run code/full_harness.py first")
    with open(full_path) as handle:
        rows = json.load(handle)
    check("80 render cells present", len(rows) == 80,
          "found %d rows" % len(rows))
    paths = sorted({row["path"] for row in rows})
    payloads = sorted({row["payload"] for row in rows})
    check("8 render paths x 10 payloads",
          paths == ["A", "B", "C", "D", "E", "F", "G", "H"]
          and payloads == ["B1", "B2", "B3", "B4", "P1", "P2", "P3",
                           "P4", "P5", "P6"],
          "paths=%s payloads=%s" % (paths, payloads))

    outcome = {(row["path"], row["payload"]): row["outcome"] for row in rows}

    # --- Check 2: the differential (8/8 escaped vs 0/8 escaped) ---
    for path in UNSANDBOXED:
        escaped = sum(1 for p in ESCAPE_CLASS
                      if outcome[(path, p)] == "escaped")
        check("path %s (unsandboxed) escapes 8/8" % path, escaped == 8,
              "escaped %d/8" % escaped)
    for path in SANDBOXED:
        escaped = sum(1 for p in ESCAPE_CLASS
                      if outcome[(path, p)] == "escaped")
        check("path %s (sandboxed) escapes 0/8" % path, escaped == 0,
              "escaped %d/8" % escaped)

    # --- Check 3: benign controls behave on every path ---
    for payload in ("P1", "B4"):
        ok = all(outcome[(path, payload)] == "engine-eval"
                 for path in UNSANDBOXED + SANDBOXED)
        check("%s is engine-eval on all 8 paths" % payload, ok)

    # --- Check 4: vLLM kwargs-override logic replay ---
    demo_path = os.path.join(RESULTS, "vllm_kwargs_override_demo.json")
    if not os.path.exists(demo_path):
        fail("vllm_kwargs_override_demo.json missing; "
             "run code/vllm_kwargs_override_demo.py first")
    with open(demo_path) as handle:
        demo = json.load(handle)
    check("pre-fix merge resolves attacker template",
          demo.get("vulnerable_merge_resolved_template_is_attacker_controlled")
          is True)
    check("fixed merge blocks smuggled chat_template key",
          str(demo.get("fixed_merge_outcome", "")).startswith("BLOCKED"))

    # --- Check 5: fresh outputs match committed expected outputs ---
    # rendered_head is excluded from strict comparison: it embeds the local
    # canary path (machine-dependent) and, for B1, the live count of loaded
    # object subclasses (import-set-dependent). Both are diagnostics; the
    # security-relevant signal is the outcome label, checked above and here.
    semantic = ("path", "path_label", "render_provenance", "payload",
                "payload_name", "payload_class", "outcome")
    for name in ("full_results.json", "vllm_kwargs_override_demo.json"):
        with open(os.path.join(RESULTS, name)) as handle:
            fresh = json.load(handle)
        with open(os.path.join(EXPECTED, name)) as handle:
            expected = json.load(handle)
        if name == "full_results.json":
            fresh_sem = [{k: row[k] for k in semantic} for row in fresh]
            exp_sem = [{k: row[k] for k in semantic} for row in expected]
            check("%s semantic fields match committed expected output" % name,
                  fresh_sem == exp_sem)
            # Positive control: every RCE-class escape on an unsandboxed
            # path actually exfiltrated the canary file's content.
            canary = "S4-ESCAPE-CANARY-9f3a7b"
            rce_rows = [row for row in fresh
                        if row["path"] in UNSANDBOXED
                        and row["payload"] in ("P3", "P4", "P5", "P6")]
            check("RCE escapes exfiltrated the canary content",
                  all(canary in (row["rendered_head"] or "")
                      for row in rce_rows),
                  "%d rows" % len(rce_rows))
        else:
            check("%s matches committed expected output" % name,
                  fresh == expected)

    print("ALL CHECKS PASSED: headline numbers reproduced.")


if __name__ == "__main__":
    main()
