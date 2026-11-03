"""Optional local Windows x64 toolchain download; verifies official SHA-256."""
import hashlib,json,pathlib,urllib.request,zipfile,sys
root=pathlib.Path(__file__).resolve().parents[1]/'.tools';root.mkdir(exist_ok=True)
version='0.17.0'
with urllib.request.urlopen('https://ziglang.org/download/index.json',timeout=30) as r:index=json.load(r)
entry=index[version]['x86_64-windows'];archive=root/f'zig-{version}.zip'
if not archive.exists():urllib.request.urlretrieve(entry['tarball'],archive)
if hashlib.sha256(archive.read_bytes()).hexdigest()!=entry['shasum']:sys.exit('Toolchain checksum mismatch')
with zipfile.ZipFile(archive) as z:
 for name in z.namelist():
  if not (root/name).resolve().is_relative_to(root.resolve()):sys.exit('Unsafe archive member')
 z.extractall(root)
print(next(root.glob('*/zig.exe')).relative_to(root.parent))
