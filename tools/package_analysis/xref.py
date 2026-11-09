import sys, re, struct, pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def load(path):
    pe = pefile.PE(path)
    return pe, open(path, "rb").read()

def find_strings(pe, data, pattern, wide=False):
    """Return list of (va, text) for strings matching regex pattern in the image."""
    base = pe.OPTIONAL_HEADER.ImageBase
    res = []
    for s in pe.sections:
        raw = data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
        rx = rb"(?:[\x20-\x7e]\x00){4,}" if wide else rb"[\x20-\x7e]{4,}"
        for m in re.finditer(rx, raw):
            t = m.group().decode("utf-16le" if wide else "ascii")
            if re.search(pattern, t):
                res.append((base + s.VirtualAddress + m.start(), t))
    return res

def text_sections(pe):
    return [s for s in pe.sections if s.Characteristics & 0x20000000]  # executable

def xrefs(pe, data, targets):
    """RIP-relative refs (lea/mov [rip+disp]) to any VA in targets. Returns {target: [instr_va]}"""
    base = pe.OPTIONAL_HEADER.ImageBase
    tset = set(targets)
    out = {t: [] for t in tset}
    for s in text_sections(pe):
        raw = data[s.PointerToRawData:s.PointerToRawData + min(s.SizeOfRawData, s.Misc_VirtualSize)]
        sva = base + s.VirtualAddress
        # scan for 4-byte disp where (addr_after_disp + disp) hits a target; instr end is disp_off+4 (+imm if any, ignore)
        for i in range(0, len(raw) - 4):
            disp = struct.unpack_from("<i", raw, i)[0]
            for extra in (0, 1, 4):
                tgt = sva + i + 4 + extra + disp
                if tgt in tset:
                    # require a plausible rip-relative modrm byte (mod=00, rm=101) just before
                    if i >= 1 and (raw[i - 1] & 0xC7) == 0x05:
                        out[tgt].append(sva + i - 3)
    return out

def func_bounds(pe, va):
    base = pe.OPTIONAL_HEADER.ImageBase
    rva = va - base
    for rf in pe.DIRECTORY_ENTRY_EXCEPTION:
        if rf.struct.BeginAddress <= rva < rf.struct.EndAddress:
            return base + rf.struct.BeginAddress, base + rf.struct.EndAddress
    return None

def read_va(pe, data, va, n):
    base = pe.OPTIONAL_HEADER.ImageBase
    rva = va - base
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            off = s.PointerToRawData + (rva - s.VirtualAddress)
            return data[off:off + n]
    return b""

def disasm(pe, data, start, end, symbolize=None, limit=400):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    code = read_va(pe, data, start, end - start)
    n = 0
    for ins in md.disasm(code, start):
        line = "%x:  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str)
        if symbolize:
            note = symbolize(ins)
            if note:
                line += "    ; " + note
        print(line)
        n += 1
        if n >= limit:
            print("... (truncated)")
            break

def make_symbolizer(pe, data):
    """Annotate rip-relative operands with the ASCII/UTF-16 string they point to."""
    def sym(ins):
        m = re.search(r"\[rip ([+-]) (0x[0-9a-f]+)\]", ins.op_str)
        if not m:
            return ""
        d = int(m.group(2), 16)
        tgt = ins.address + ins.size + (d if m.group(1) == "+" else -d)
        raw = read_va(pe, data, tgt, 80)
        a = re.match(rb"[\x20-\x7e]{4,}", raw)
        if a:
            return "-> '%s'" % a.group().decode()
        w = re.match(rb"(?:[\x20-\x7e]\x00){4,}", raw)
        if w:
            return "-> L'%s'" % w.group().decode("utf-16le")
        return "-> %x" % tgt
    return sym
