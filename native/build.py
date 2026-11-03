"""Build user-mode Windows x64 validation artifacts; never installs a driver."""
import argparse,json,pathlib,shutil,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--zig',default=shutil.which('zig'));a=p.parse_args()
if not a.zig:sys.exit('Zig not found. Use --zig PATH or run tools/fetch_zig.py first.')
tool=str(pathlib.Path(a.zig).resolve())
common=[tool,'cc','-std=c11','-Wall','-Wextra','-Werror','-O2','-ffreestanding','-fno-builtin']
commands=[common+['-c','sae_codec.c','-o','sae_codec.obj'],common+['-c','sae_session.c','-o','sae_session.obj'],
 [tool,'build-lib','-dynamic','-fno-entry','sae_codec.obj','sae_session.obj','-femit-bin=sae_codec.dll']]
for command in commands:subprocess.run(command,cwd=ROOT,check=True)
print('Built a no-CRT user-mode validation DLL and objects. No driver or installer produced.')
