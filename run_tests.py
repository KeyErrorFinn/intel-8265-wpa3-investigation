"""Run the curated offline suite without vendor binaries or WDK assets."""
import argparse,pathlib,subprocess,sys
root=pathlib.Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--native',action='store_true');a=p.parse_args()
subprocess.run([sys.executable,'test_sae_wdi_codec.py'],cwd=root,check=True)
if a.native:
 for name in ['test_native.py','test_session.py','test_intel_binding.py','test_tx_body.py']:
  subprocess.run([sys.executable,str(root/'native'/name)],cwd=root,check=True)
