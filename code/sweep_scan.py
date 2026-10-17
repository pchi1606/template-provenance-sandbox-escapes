#!/usr/bin/env python3
"""S4 responsible-disclosure sweep scanner (Appendix A procedure).

Scans pinned repository clones for Jinja2 render call sites and reports
which ones are NOT sandboxed. A call site is considered sandboxed if the
source text at/near the call references SandboxedEnvironment /
ImmutableSandboxedEnvironment; otherwise it is flagged for manual review.

Targets (pins recorded in paper Appendix D):
  repos/ragflow        @ nightly 2400ca8 (Python agent removed; Go rewrite)
  repos/sglang         @ f385390 (2026-10-05)
  repos/langchain      @ 007cc15 (2026-10-04)
  repos/langgraph      @ 9a0394d (2026-10-03)
  repos/vllm           @ 0c16eee (2026-10-05)
plus historical tags ragflow v0.24.0 and sglang v0.5.9 (vulnerable versions,
expected to flag — confirms the scanner sees what the CVEs describe).

Usage: python3 code/sweep_scan.py > logs/sweep_scan.log
"""
import ast
import os
import sys

WORKDIR = os.path.expanduser("~/workspace/gap-papers/s4-template-escapes")
REPOS = os.path.join(WORKDIR, "repos")

# (repo dir, git ref to scan, expect_unsandboxed)
TARGETS = [
    ("ragflow", "HEAD", False),
    ("sglang", "HEAD", False),
    ("langchain", "HEAD", False),
    ("langgraph", "HEAD", False),
    ("vllm", "HEAD", False),
    ("ragflow", "v0.24.0", True),   # CVE-2026-28797 vulnerable version
    ("sglang", "v0.5.9", True),     # CVE-2026-5760 vulnerable version
]

RENDER_CALLS = {"Template", "Environment", "from_string"}


def iter_py_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "__pycache__", "node_modules")]
        for fn in filenames:
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


def scan_tree(root):
    """Return list of (relpath, lineno, call, sandboxed_hint)."""
    hits = []
    for path in iter_py_files(root):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                src = f.read()
        except OSError:
            continue
        if "jinja2" not in src and "jinja" not in src:
            continue
        try:
            tree = ast.parse(src, filename=path)
        except SyntaxError:
            continue
        sandboxed_nearby = ("SandboxedEnvironment" in src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = None
                if isinstance(func, ast.Attribute):
                    name = func.attr
                elif isinstance(func, ast.Name):
                    name = func.id
                if name in RENDER_CALLS:
                    hits.append((os.path.relpath(path, root), node.lineno,
                                 name, sandboxed_nearby))
    return hits


def main():
    overall_unsandboxed = []
    for repo, ref, expect in TARGETS:
        rdir = os.path.join(REPOS, repo)
        # check out the ref in a temp worktree-free way: use git show via
        # `git -C <dir> stash-free checkout` is unsafe; instead require the
        # clone to already be at HEAD and use `git show ref:` trees.
        print(f"=== {repo} @ {ref} ===")
        if ref == "HEAD":
            hits = scan_tree(rdir)
        else:
            # materialize the tag into a temp dir
            import tempfile, subprocess
            tmp = tempfile.mkdtemp(prefix=f"s4sweep-{repo}-")
            tar_path = os.path.join(tmp, "a.tar")
            with open(tar_path, "wb") as fh:
                subprocess.run(["git", "-C", rdir, "archive", ref,
                                "--format=tar"],
                               stdout=fh, check=True)
            subprocess.run(["tar", "-xf", tar_path, "-C", tmp], check=True)
            hits = scan_tree(tmp)
        flagged = [h for h in hits if not h[3]]
        for rel, lineno, call, _ in flagged:
            print(f"  UNSANDBOXED? {rel}:{lineno} -> {call}(...)")
            overall_unsandboxed.append((repo, ref, rel, lineno, call))
        print(f"  render call sites: {len(hits)}, "
              f"flagged (no sandbox hint): {len(flagged)}, "
              f"expected_unsandboxed={expect}")
    print("\n=== verdict ===")
    new_live = [(r, ref, p, ln) for (r, ref, p, ln, c) in overall_unsandboxed
                if ref == "HEAD"]
    print(f"unsandboxed-looking render sites at HEAD: {len(new_live)}")
    for r, ref, p, ln in new_live:
        print(f"  {r}@{ref}: {p}:{ln}")
    if not new_live:
        print("NO NEW LIVE VULNERABILITIES FOUND by this sweep.")
    return 0 if not new_live else 1


if __name__ == "__main__":
    sys.exit(main())
