"""User-mode native DLL tests against the independently implemented codec."""
import ctypes as t,pathlib,sys,unittest,struct,random,json,hashlib
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent));import sae_wdi_codec as oracle
class Blob(t.Structure):_fields_=[('offset',t.c_uint32),('length',t.c_uint32)]
class Request(t.Structure):
    _fields_=[('bssid',t.c_ubyte*6),('group',t.c_uint16),('request_type',t.c_uint32),('status',t.c_uint32),('flags',t.c_uint32),
      ('send_confirm',t.c_uint16),('reserved',t.c_uint16),('scalar',Blob),('element',Blob),('token',Blob),('rejected_groups',Blob),('confirm',Blob),('owned_length',t.c_size_t)]
class Indication(t.Structure):
    _fields_=[('bssid',t.c_ubyte*6),('reserved',t.c_uint16),('kind',t.c_uint32),('status',t.c_uint32),('flags',t.c_uint32),
      ('commit',t.c_void_p),('commit_length',t.c_size_t),('confirm',t.c_void_p),('confirm_length',t.c_size_t)]
DLL=ROOT/('sae_codec_nocrt.dll' if '--no-crt' in sys.argv else 'sae_codec.dll')
lib=t.CDLL(str(DLL))
lib.sae_parse_request.argtypes=[t.c_void_p,t.c_size_t,t.c_uint32,t.c_void_p,t.c_size_t,t.POINTER(Request)]
lib.sae_parse_request.restype=t.c_int
lib.sae_release_request.argtypes=[t.c_void_p,t.c_size_t,t.POINTER(Request)]
lib.sae_encode_indication.argtypes=[t.POINTER(Indication),t.c_uint32,t.c_void_p,t.c_size_t,t.POINTER(t.c_size_t)]
lib.sae_encode_indication.restype=t.c_int
lib.sae_write_header.argtypes=[t.c_void_p,t.c_size_t,t.c_uint16,t.c_uint32,t.c_uint32,t.c_uint32]
lib.sae_write_header.restype=t.c_int
lib.sae_encode_auth_body_indication.argtypes=[t.c_void_p,t.c_void_p,t.c_size_t,t.c_uint32,t.c_void_p,t.c_size_t,t.POINTER(t.c_size_t)]
lib.sae_encode_auth_body_indication.restype=t.c_int
lib.sae_encode_intel_rx_indication.argtypes=[t.c_void_p,t.c_size_t,t.c_void_p,t.c_void_p,t.c_uint32,t.c_void_p,t.c_size_t,t.POINTER(t.c_size_t)]
lib.sae_encode_intel_rx_indication.restype=t.c_int
MAC=bytes.fromhex('021122334455');VERSION=0x1010c
CORPUS=[oracle.Request(MAC,0,oracle.Commit(19,bytes(range(32)),bytes(range(64)))),
 oracle.Request(MAC,4,oracle.Commit(20,b'S'*48,b'E'*96,b'TOKEN',b'\x13\0')),
 oracle.Request(MAC,1,confirmation=oracle.Confirmation(3,b'C'*32)),oracle.Request(MAC,2,status=53),oracle.Request(MAC,3)]

def decode(data,version=VERSION):
    source=t.create_string_buffer(data);owned=t.create_string_buffer(max(1,len(data)));out=Request()
    result=lib.sae_parse_request(source,len(data),version,owned,len(data),t.byref(out))
    return result,source,owned,out

class NativeTests(unittest.TestCase):
    def compare_request(self,expected,owned,out):
        self.assertEqual(bytes(out.bssid),expected.bssid);self.assertEqual(out.request_type,expected.request_type)
        def blob(field):return owned.raw[field.offset:field.offset+field.length]
        if expected.commit:
            self.assertEqual(out.group,expected.commit.group)
            for name in ['scalar','element','token','rejected_groups']:
                self.assertEqual(blob(getattr(out,name)),getattr(expected.commit,name) or b'')
        if expected.confirmation:
            self.assertEqual(out.send_confirm,expected.confirmation.send_confirm);self.assertEqual(blob(out.confirm),expected.confirmation.confirm)
        if expected.status is not None:self.assertEqual(out.status,expected.status)

    def test_golden_requests_and_owned_lifetime(self):
        for item in CORPUS:
            wire=oracle.encode_request(item);result,source,owned,out=decode(wire)
            self.assertEqual(result,0);self.assertEqual(out.owned_length,len(wire));self.compare_request(item,owned,out)
            t.memset(source,0,len(wire));self.compare_request(item,owned,out)
            lib.sae_release_request(owned,len(wire),t.byref(out))
            self.assertEqual(owned.raw[:len(wire)],bytes(len(wire)));self.assertEqual(bytes(out),bytes(t.sizeof(out)))

    def test_actual_windows_serializer_vectors(self):
        fixture=ROOT.parent/'tests/fixtures/windows-sae-vectors.json'
        self.assertTrue(fixture.exists(),'Expected checked-in synthetic fixture vectors')
        rows=json.loads(fixture.read_text())['cases'];self.assertEqual(len(rows),5)
        for row in rows:
            packet=bytes.fromhex(row['packetHex']);payload=packet[16:]
            self.assertEqual(packet[:16],bytes(16));self.assertTrue(row['originalGenericSerializerExecuted'])
            version=int(row['version'],16);expected=oracle.decode_request(payload,version)
            result,source,owned,out=decode(payload,version)
            self.assertEqual(result,0);self.compare_request(expected,owned,out)

    def test_all_truncations_and_failure_erasure(self):
        wire=oracle.encode_request(CORPUS[0])
        for n in range(len(wire)):
            result,source,owned,out=decode(wire[:n])
            self.assertNotEqual(result,0);self.assertEqual(bytes(out),bytes(t.sizeof(out)))
            self.assertEqual(owned.raw[:n],bytes(n))

    def test_mutation_differential(self):
        rng=random.Random(8265);base=oracle.encode_request(CORPUS[0]);cases=0
        for i in range(1500):
            data=bytearray(base)
            for _ in range(1+rng.randrange(4)):data[rng.randrange(len(data))]=rng.randrange(256)
            if i%4==0:data.extend(struct.pack('<HH',0xfffe,3)+b'new')
            try:expected=oracle.decode_request(data);valid=True
            except oracle.CodecError:valid=False
            result,source,owned,out=decode(bytes(data));self.assertEqual(result==0,valid,f'case {i}')
            if valid:self.compare_request(expected,owned,out)
            cases+=1
        self.assertEqual(cases,1500)

    def test_versions_required_fields_duplicates(self):
        wire=oracle.encode_request(CORPUS[1])
        self.assertEqual(decode(wire,0x10108)[0],3);self.assertEqual(decode(wire,0x10107)[0],3)
        for data in [b'',b'\x02',wire+struct.pack('<HH',2,6)+MAC,
          struct.pack('<HH',2,5)+MAC[:5],struct.pack('<HH',0x14f,4)+bytes(4)]:self.assertNotEqual(decode(data)[0],0)

    def test_overlapping_input_copy(self):
        wire=oracle.encode_request(CORPUS[0]);storage=t.create_string_buffer(len(wire)+4);t.memmove(storage,wire,len(wire));out=Request()
        self.assertEqual(lib.sae_parse_request(storage,len(wire),VERSION,t.addressof(storage)+4,len(wire),t.byref(out)),0)
        self.assertEqual(storage.raw[4:4+len(wire)],wire)

    def test_output_capacity_does_not_write(self):
        wire=oracle.encode_request(CORPUS[0]);source=t.create_string_buffer(wire);owned=t.create_string_buffer(b'Z'*len(wire));out=Request()
        self.assertEqual(lib.sae_parse_request(source,len(wire),VERSION,owned,len(wire)-1,t.byref(out)),2)
        self.assertEqual(owned.raw[:len(wire)],b'Z'*len(wire));self.assertEqual(bytes(out),bytes(t.sizeof(out)))

    def test_indications_against_oracle(self):
        for kind in range(5):
            for n in [1,32,65535]:
                raw=bytes((x%251 for x in range(n)));storage=t.create_string_buffer(raw)
                item=Indication();item.bssid[:]=MAC;item.kind=kind;item.status=53
                kwargs={}
                if kind==1:item.commit=t.addressof(storage);item.commit_length=n;kwargs['commit_response']=raw
                if kind==2:item.confirm=t.addressof(storage);item.confirm_length=n;kwargs['confirm_response']=raw
                if kind==3:item.flags=4;kwargs['status']=53
                expected=oracle.encode_indication(MAC,kind,**kwargs);needed=t.c_size_t()
                self.assertEqual(lib.sae_encode_indication(t.byref(item),VERSION,None,0,t.byref(needed)),2)
                self.assertEqual(needed.value,len(expected));out=t.create_string_buffer(b'Q'*(needed.value+8))
                self.assertEqual(lib.sae_encode_indication(t.byref(item),VERSION,out,needed.value-1,t.byref(needed)),2)
                self.assertEqual(out.raw[:needed.value+8],b'Q'*(needed.value+8))
                self.assertEqual(lib.sae_encode_indication(t.byref(item),VERSION,out,needed.value,t.byref(needed)),0)
                self.assertEqual(out.raw[:needed.value],expected);self.assertEqual(out.raw[needed.value:needed.value+8],b'Q'*8)

    def test_indication_invalid_inputs(self):
        item=Indication();item.bssid[:]=MAC;needed=t.c_size_t()
        for kind in (1,2,3,5):
            item.kind=kind;self.assertEqual(lib.sae_encode_indication(t.byref(item),VERSION,None,0,t.byref(needed)),1)
        item.kind=0;item.commit_length=65536
        self.assertEqual(lib.sae_encode_indication(t.byref(item),VERSION,None,0,t.byref(needed)),1)

    def test_exact_wdi_header(self):
        out=t.create_string_buffer(b'Z'*24)
        self.assertEqual(lib.sae_write_header(out,15,0x1234,0xc000000d,0xdeadbeef,0x12345678),2)
        self.assertEqual(out.raw[:24],b'Z'*24)
        self.assertEqual(lib.sae_write_header(out,16,0x1234,0xc000000d,0xdeadbeef,0x12345678),0)
        self.assertEqual(out.raw[:16],struct.pack('<HHIII',0x1234,0,0xc000000d,0xdeadbeef,0x12345678));self.assertEqual(out.raw[16:24],b'Z'*8)

    def test_intel_rx_event_adapter(self):
        peer=MAC;local=bytes.fromhex('0266778899aa');peerbuf=t.create_string_buffer(peer);localbuf=t.create_string_buffer(local)
        body=struct.pack('<HHH',3,1,76)+bytes(range(96))
        header=bytes.fromhex('b0000000')+local+peer+peer+bytes(2)
        frame=t.create_string_buffer(header+body);parsed=t.create_string_buffer(0x5d0)
        def reset():
            frame.raw=header+body+b'\0';parsed.raw=bytes(0x5d0)
            struct.pack_into('<Q',parsed,8,t.addressof(frame));struct.pack_into('<QII',parsed,0x5c0,t.addressof(frame)+24,len(body),0)
        def encode(size=0x5d0):
            n=t.c_size_t(999);out=t.create_string_buffer(1024)
            status=lib.sae_encode_intel_rx_indication(parsed,size,peerbuf,localbuf,VERSION,out,len(out),t.byref(n))
            return status,out.raw[:n.value],n.value
        for parse_ok in (0,1):
            reset();struct.pack_into('<I',parsed,0x5cc,parse_ok)
            status,payload,n=encode();self.assertEqual(status,0)
            self.assertEqual(payload,oracle.encode_indication(peer,1,commit_response=body))
        for header_offset in (0,1,4,10,16):
            reset();frame[header_offset]=bytes([frame.raw[header_offset]^1])
            status,payload,n=encode();self.assertEqual((status,n),(1,0))
        reset();self.assertEqual(encode(0x5cf)[::2],(1,0))
        for offset,value in [(8,0),(0x5c0,t.addressof(frame)+25)]:
            reset();struct.pack_into('<Q',parsed,offset,value);self.assertEqual(encode()[::2],(1,0))
        for length in (0,5,65536):
            reset();struct.pack_into('<I',parsed,0x5c8,length);self.assertEqual(encode()[::2],(1,0))

    def test_auth_body_receive_adapter(self):
        mac=t.create_string_buffer(MAC)
        for transaction in (1,2):
            for status in (0,76,77,126):
                body=struct.pack('<HHH',3,transaction,status)+bytes(range(96));src=t.create_string_buffer(body);n=t.c_size_t()
                self.assertEqual(lib.sae_encode_auth_body_indication(mac,src,len(body),VERSION,None,0,t.byref(n)),2)
                out=t.create_string_buffer(n.value)
                self.assertEqual(lib.sae_encode_auth_body_indication(mac,src,len(body),VERSION,out,n.value,t.byref(n)),0)
                expected=oracle.encode_indication(MAC,transaction,**({'commit_response':body} if transaction==1 else {'confirm_response':body}))
                self.assertEqual(out.raw,expected)
        for body in [b'',b'\x03\0\x01\0\0',struct.pack('<HHH',0,1,0),struct.pack('<HHH',3,3,0),b'\xb0\0'+bytes(28)]:
            src=t.create_string_buffer(body);n=t.c_size_t(123)
            self.assertEqual(lib.sae_encode_auth_body_indication(mac,src,len(body),VERSION,None,0,t.byref(n)),1);self.assertEqual(n.value,0)

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeTests))
    report={'testsRun':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'differentialMutations':1500,
      'dllFile':DLL.name,'dllSha256':hashlib.sha256(DLL.read_bytes()).hexdigest(),'requestStructBytes':t.sizeof(Request),'indicationStructBytes':t.sizeof(Indication),
      'kind':'Native user-mode codec tests; no kernel driver or live WDI/radio integration'}
    (ROOT/('test-nocrt-results.json' if '--no-crt' in sys.argv else 'test-results.json')).write_text(json.dumps(report,indent=2));raise SystemExit(0 if result.wasSuccessful() else 1)
