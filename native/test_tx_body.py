"""Native TX-body encoding tests using synthetic inputs; no driver execution."""
import ctypes as t, pathlib,sys,unittest,struct,json
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT));import test_native as n
sys.path.insert(0,str(ROOT.parent))
lib=n.lib
lib.sae_encode_tx_auth_body.argtypes=[t.POINTER(n.Request),t.c_void_p,t.c_size_t,t.c_void_p,t.c_size_t,t.POINTER(t.c_size_t)]
lib.sae_encode_tx_auth_body.restype=t.c_int
oracle=n.oracle
def fixture(kind=0,group=19,token=b'',rejected=b''):
    prime={19:32,20:48,21:66}.get(group,32)
    if kind in (0,4):
        req=oracle.Request(n.MAC,kind,oracle.Commit(group,b'S'*prime,b'E'*(2*prime),token or None,rejected or None))
    elif kind==1:req=oracle.Request(n.MAC,1,confirmation=oracle.Confirmation(7,b'C'*32))
    elif kind==2:req=oracle.Request(n.MAC,2,status=53)
    else:req=oracle.Request(n.MAC,3)
    rc,source,owned,r=n.decode(oracle.encode_request(req));assert rc==0
    return source,owned,r
def encode(r,owned,cap=4096):
    out=t.create_string_buffer(b'\xa5'*max(1,cap));written=t.c_size_t()
    rc=lib.sae_encode_tx_auth_body(t.byref(r),owned,len(owned.raw),out,cap,t.byref(written))
    return rc,out,written.value
class TxTests(unittest.TestCase):
    def test_classic_commit_wire_order(self):
        for g,p in ((19,32),(20,48),(21,66)):
            for token in (b'',b'TOKEN'):
                s,o,r=fixture(group=g,token=token)
                rc,out,w=encode(r,o)
                expected=struct.pack('<HHHH',3,1,0,g)+token+b'S'*p+b'E'*(2*p)
                self.assertEqual(rc,0);self.assertEqual(out.raw[:w],expected)
    def test_h2e_extension_order_and_status(self):
        s,o,r=fixture(4,20,b'TOKEN',b'\x13\0\x15\0')
        rc,out,w=encode(r,o)
        expected=struct.pack('<HHHH',3,1,126,20)+b'S'*48+b'E'*96+b'\xff\x05\x5c\x13\0\x15\0'+b'\xff\x06\x5dTOKEN'
        self.assertEqual(rc,0);self.assertEqual(out.raw[:w],expected)
    def test_confirm_does_not_increment_os_counter(self):
        s,o,r=fixture(1);rc,out,w=encode(r,o)
        self.assertEqual(rc,0);self.assertEqual(out.raw[:w],struct.pack('<HHHH',3,2,0,7)+b'C'*32)
    def test_local_results_do_not_emit_radio_frame(self):
        for kind in (2,3):
            s,o,r=fixture(kind);rc,out,w=encode(r,o)
            self.assertEqual((rc,w),(4,0));self.assertEqual(out.raw[:10],b'\xa5'*10)
    def test_capacity_and_guard_bytes(self):
        s,o,r=fixture();rc,out,needed=encode(r,o)
        for cap in range(needed):
            rc,out,w=encode(r,o,cap)
            self.assertEqual((rc,w),(2,needed));self.assertEqual(out.raw[:-1],b'\xa5'*max(1,cap))
        rc,out,w=encode(r,o,needed+8)
        self.assertEqual(out.raw[w:w+8],b'\xa5'*8)
    def test_invalid_bounds_and_unsupported_group(self):
        s,o,r=fixture(group=22);self.assertEqual(encode(r,o)[0],5)
        s,o,r=fixture();r.scalar.offset=0xffffffff;self.assertEqual(encode(r,o)[0],1)
        s,o,r=fixture();r.element.length-=1;self.assertEqual(encode(r,o)[0],1)
        s,o,r=fixture(4,token=b'T'*255);self.assertEqual(encode(r,o)[0],1)
        s,o,r=fixture(4,rejected=b'\x13');self.assertEqual(encode(r,o)[0],1)
        s,o,r=fixture(rejected=b'\x13\0');self.assertEqual(encode(r,o)[0],1)
    def test_overlap_rejected(self):
        s,o,r=fixture();w=t.c_size_t();before=o.raw
        self.assertEqual(lib.sae_encode_tx_auth_body(t.byref(r),o,r.owned_length,o,r.owned_length,t.byref(w)),1)
        self.assertEqual(o.raw,before)
if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(TxTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    (ROOT/('tx-nocrt-results.json' if '--no-crt' in sys.argv else 'tx-results.json')).write_text(json.dumps({'tests':result.testsRun,'success':result.wasSuccessful(),'dll':n.DLL.name,'scope':'native encoding with synthetic inputs, no live driver'}))
    sys.exit(not result.wasSuccessful())
