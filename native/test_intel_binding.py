"""Native identity adapter checked against recorded synthetic object views.

Fixture records object views from an earlier controlled emulation experiment.
These tests consume saved views; they do not execute the original driver.
Synthetic mutations test bounded rejection. No live hook or concurrency proof.
"""
import ctypes as t,json,pathlib,sys,struct,unittest
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT));import test_session as n
lib=n.lib
class Identity(t.Structure):
 _fields_=[('port_interface',t.c_uint64),('command',t.c_uint64),('request',t.c_uint64),
           ('transaction',t.c_uint32),('ihv',t.c_uint32),('ndis_port',t.c_uint32),
           ('wdi_port',t.c_uint16),('reserved',t.c_uint16)]
assert t.sizeof(Identity)==40
lib.sae_intel_capture_connect.argtypes=[t.c_uint64,t.c_uint64,t.c_void_p,t.c_size_t,
 t.c_uint64,t.c_void_p,t.c_size_t,t.POINTER(Identity)]
lib.sae_intel_capture_connect.restype=t.c_int
lib.sae_intel_begin_captured_connect.argtypes=[t.POINTER(n.Session),t.POINTER(Identity),
 t.c_uint64,t.c_void_p,t.c_void_p,t.c_int,t.POINTER(t.c_uint32)]
lib.sae_intel_begin_captured_connect.restype=t.c_int
FIXTURE=json.loads((ROOT.parent/'tests/fixtures/connect-object-views.json').read_text())
ROWS={s['label']:s for s in FIXTURE['snapshots']}
VALID=ROWS['run-before-real-parser']
def capture(row=VALID,pv=None,cv=None,pn=None,cn=None,command=None,image=None):
 p=bytes.fromhex(row['portView']) if pv is None else pv
 c=bytes.fromhex(row.get('taskView','')) if cv is None else cv
 out=Identity()
 status=lib.sae_intel_capture_connect(int(row['imageBase'],16) if image is None else image,
  int(row['portInterfaceAddress'],16),p,len(p) if pn is None else pn,
  int(row['task'],16) if command is None else command,c,len(c) if cn is None else cn,t.byref(out))
 return status,out
def mutation(offset,value,fmt='<Q',port=False):
 b=bytearray.fromhex(VALID['portView' if port else 'taskView'])
 struct.pack_into(fmt,b,offset,value)
 return capture(**({'pv':bytes(b)} if port else {'cv':bytes(b)}))
class IntelBindingTests(unittest.TestCase):
 def test_actual_original_objects_capture(self):
  rc,i=capture();self.assertEqual(rc,0)
  self.assertEqual((i.transaction,i.ihv,i.ndis_port,i.wdi_port),(0x12345678,0xabcddcba,7,7))
  self.assertEqual(i.command,int(VALID['task'],16));self.assertNotEqual(i.request,0)
 def test_original_worker_slot_before_port_binding_rejected(self):
  self.assertEqual(capture(ROWS['worker-before-run'])[0],2)
 def test_original_destructor_entry_is_not_detectable_by_identity_alone(self):
  # This is intentionally accepted as a byte identity. It is NOT a safe task
  # reference: actual hook lifetime serialization must exclude this boundary.
  self.assertEqual(capture(ROWS['destructor-entry'])[0],0)
  self.assertEqual(capture(ROWS['inside-free-before-slot-clear'])[0],3)
 def test_after_original_clear_no_task(self):
  self.assertEqual(capture(ROWS['after-worker'])[0],1)
 def test_wrong_slot_or_bound_port_rejected(self):
  self.assertEqual(mutation(0xb8,0,port=True)[0],2)
  self.assertEqual(mutation(8,0)[0],2)
  self.assertEqual(capture(command=1)[0],2)
 def test_completed_oid_is_not_mistaken_for_ended_async_task(self):
  self.assertEqual(mutation(0x60,1,'<I')[0],0)
 def test_nonconnect_or_wrong_vtable_rejected(self):
  self.assertEqual(mutation(0x10,0xe4400064,'<I')[0],3)
  self.assertEqual(mutation(0,0)[0],3)
  self.assertEqual(mutation(0,0,port=True)[0],3)
 def test_short_views_and_image_overflow(self):
  for k in range(0xc0):self.assertEqual(capture(pn=k)[0],1)
  for k in range(0x9c):self.assertEqual(capture(cn=k)[0],1)
  self.assertEqual(capture(image=2**64-1)[0],1)
 def test_output_overlap_does_not_corrupt_original_object_view(self):
  p=bytes.fromhex(VALID['portView']);c=t.create_string_buffer(bytes.fromhex(VALID['taskView']))
  before=c.raw
  self.assertEqual(lib.sae_intel_capture_connect(int(VALID['imageBase'],16),
   int(VALID['portInterfaceAddress'],16),p,len(p),int(VALID['task'],16),c,len(c)-1,
   t.cast(c,t.POINTER(Identity))),1)
  self.assertEqual(c.raw,before)
 def test_inconsistent_port_header_or_missing_request(self):
  for off,v,fmt in ((0x44,65543,'<I'),(0x8e,1,'<H'),(0x48,0,'<Q')):
   self.assertEqual(mutation(off,v,fmt)[0],1)
 def test_native_begin_maps_original_transaction_and_fresh_gate(self):
  rc,i=capture();self.assertEqual(rc,0);s=n.Session();e=t.c_uint32()
  self.assertEqual(lib.sae_intel_begin_captured_connect(t.byref(s),t.byref(i),77,
   n.PEER,n.LOCAL,1,t.byref(e)),0)
  self.assertEqual((s.generation,s.port,s.transaction,e.value),(77,7,0x12345678,16))
  consume=t.c_int();self.assertEqual(lib.sae_session_legacy_gate(t.byref(s),77,t.byref(consume)),0)
  self.assertEqual(consume.value,1)
 def test_generation_still_monotonic_and_context_not_reusable_while_active(self):
  _,i=capture();s=n.Session();e=t.c_uint32()
  def begin(g):return lib.sae_intel_begin_captured_connect(t.byref(s),t.byref(i),g,
   n.PEER,n.LOCAL,1,t.byref(e))
  self.assertEqual(begin(1),0);self.assertEqual(begin(1),2);self.assertEqual(begin(2),3)
 def test_cached_boundary_preserves_explicit_bypass(self):
  _,i=capture();s=n.Session();e=t.c_uint32()
  self.assertEqual(lib.sae_intel_begin_captured_connect(t.byref(s),t.byref(i),1,
   n.PEER,n.LOCAL,0,t.byref(e)),0)
  self.assertEqual(e.value,32)

if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(IntelBindingTests)
 result=unittest.TextTestRunner(verbosity=2).run(suite)
 out={'dll':n.n.DLL.name,'tests':result.testsRun,'success':result.wasSuccessful(),
  'fixtureSnapshot':FIXTURE['snapshotSha256'],
  'limits':'Offline original-object views plus native adapter/session. Capture is not safe lifetime, installed hook, unique generation allocator, radio or kernel concurrency validation.'}
 (ROOT/('intel-binding-nocrt-results.json' if '--no-crt' in sys.argv else 'intel-binding-results.json')).write_text(json.dumps(out,indent=2))
 sys.exit(not result.wasSuccessful())
