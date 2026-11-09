import sys, re, pefile, datetime

def summarize(path):
    pe = pefile.PE(path, fast_load=False)
    print("==", path)
    print("machine", hex(pe.FILE_HEADER.Machine), "built",
          datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, datetime.UTC).date(),
          "imagebase", hex(pe.OPTIONAL_HEADER.ImageBase), "entry", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    for s in pe.sections:
        print("  sec %-8s va=%08x vsize=%07x raw=%07x" % (s.Name.rstrip(b"\0").decode(), s.VirtualAddress, s.Misc_VirtualSize, s.SizeOfRawData))
    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for d in pe.DIRECTORY_ENTRY_DEBUG:
            e = getattr(d, "entry", None)
            if e is not None and hasattr(e, "PdbFileName"):
                print("  pdb", e.PdbFileName.rstrip(b"\0").decode(errors="replace"))
    imps = {}
    for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        imps[d.dll.decode()] = [i.name.decode() if i.name else "#%d" % i.ordinal for i in d.imports]
    for dll, fns in imps.items():
        print("  import %-18s %d fns" % (dll, len(fns)))
    return pe, imps

def strings(path, minlen=6):
    data = open(path, "rb").read()
    out = set()
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        out.add(m.group().decode())
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data):
        out.add(m.group().decode("utf-16le"))
    return out

if __name__ == "__main__":
    for p in sys.argv[1:]:
        summarize(p)
