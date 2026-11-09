import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xref import *

# Usage: check_auth.py <driver.sys> ...
# Reports WPA3 name strings, and the auth-algo name function (legacy DOT11_AUTH_ALGO_* table vs WPA3 switch).
for path in sys.argv[1:]:
    pe, data = load(path)
    print("=====", os.path.basename(path), pe.FILE_HEADER.TimeDateStamp)
    w3 = find_strings(pe, data, r"^(WPA3 SAE|WPA3 OWE|WPA3 ENT|WPA3 ENT 192|SAE FT)$")
    leg = find_strings(pe, data, r"^DOT11_AUTH_ALGO_\w+$")
    print("  WPA3 strings:", [t for _, t in w3] or "none")
    print("  legacy DOT11_AUTH_ALGO_* strings:", len(leg), [t.replace("DOT11_AUTH_ALGO_", "") for _, t in leg])
    tgt = [va for va, _ in w3 + leg]
    if tgt:
        refs = xrefs(pe, data, tgt)
        funcs = {}
        for va, t in w3 + leg:
            for r in refs[va]:
                funcs.setdefault(func_bounds(pe, r), set()).add(t)
        for fb, ts in funcs.items():
            print("  func %s: %s" % ("%x-%x (%d B)" % (fb[0], fb[1], fb[1] - fb[0]) if fb else "?", sorted(ts)))
