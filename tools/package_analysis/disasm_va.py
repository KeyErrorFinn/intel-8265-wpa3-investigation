import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xref import *

# Usage: disasm_va.py <driver.sys> <start-va-hex> <end-va-hex> [max-instructions]
path, start, end = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16)
limit = int(sys.argv[4]) if len(sys.argv) > 4 else 400
pe, data = load(path)
disasm(pe, data, start, end, make_symbolizer(pe, data), limit)
