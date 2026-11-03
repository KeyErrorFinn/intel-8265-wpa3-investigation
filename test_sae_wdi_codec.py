"""Schema checks, independent wire vectors and malformed-input regressions."""
import pathlib,struct,unittest,json,hashlib,re,xml.etree.ElementTree as ET
import sae_wdi_codec as c
ROOT=pathlib.Path(__file__).resolve().parent
MAC=bytes.fromhex('021122334455')
def tlv(kind,value):return struct.pack('<HH',kind,len(value))+value

class CodecTests(unittest.TestCase):
    def setUp(self):
        self.req=c.Request(MAC,0,c.Commit(19,bytes(range(32)),bytes(range(64))))
        nested=bytes.fromhex('52010200130053012000')+bytes(range(32))+bytes.fromhex('54014000')+bytes(range(64))
        self.golden=bytes.fromhex('020006000211223344554f0104000000000050016e00')+nested

    def test_independent_commit_vector(self):
        self.assertEqual(c.encode_request(self.req),self.golden)
        self.assertEqual(c.decode_request(self.golden),self.req)

    def test_confirm_success_failure(self):
        items=[c.Request(MAC,1,confirmation=c.Confirmation(2,bytes(range(32)))),
          c.Request(MAC,2,status=35),c.Request(MAC,3)]
        for item in items:self.assertEqual(c.decode_request(c.encode_request(item)),item)

    def test_owned_input_snapshot(self):
        borrowed=bytearray(self.golden);decoded=c.decode_request(borrowed)
        borrowed[:]=bytes(len(borrowed))
        self.assertEqual(decoded,self.req)
        self.assertIsInstance(decoded.commit.scalar,bytes)

    def test_indication_vectors(self):
        prefix=bytes.fromhex('020006000211223344554b010400')
        self.assertEqual(c.encode_indication(MAC,0),prefix+bytes(4))
        raw=bytearray(b'\x03\x00\x01\x00\x00\x00')
        encoded=c.encode_indication(MAC,1,commit_response=raw)
        self.assertEqual(encoded,prefix+struct.pack('<I',1)+bytes.fromhex('4d010600')+bytes(raw))
        raw[:]=bytes(6);self.assertTrue(encoded.endswith(bytes.fromhex('030001000000')))
        self.assertEqual(c.encode_indication(MAC,2,confirm_response=b'X'),prefix+struct.pack('<I',2)+bytes.fromhex('4e01010058'))
        self.assertEqual(c.encode_indication(MAC,3,status=53),prefix+struct.pack('<I',3)+bytes.fromhex('4c01040035000000'))
        self.assertEqual(c.encode_indication(MAC,4),prefix+struct.pack('<I',4))

    def test_all_truncated_commit_prefixes_rejected(self):
        for n in range(len(self.golden)):
            with self.subTest(length=n),self.assertRaises(c.CodecError):c.decode_request(self.golden[:n])

    def test_duplicate_top_level_and_nested(self):
        with self.assertRaises(c.CodecError):c.decode_request(self.golden+tlv(c.BSSID,MAC))
        nested=tlv(c.GROUP,b'\x13\0')*2+tlv(c.SCALAR,b'A')+tlv(c.ELEMENT,b'B')
        duplicate=tlv(c.BSSID,MAC)+tlv(c.REQUEST_TYPE,bytes(4))+tlv(c.COMMIT_REQUEST,nested)
        with self.assertRaises(c.CodecError):c.decode_request(duplicate)

    def test_unknown_tlv_skipped(self):
        self.assertEqual(c.decode_request(tlv(0xfffe,b'future')+self.golden),self.req)

    def test_lengths_and_required_fields(self):
        malformed=[b'\x02',tlv(c.BSSID,b'x')+tlv(c.REQUEST_TYPE,struct.pack('<I',3)),
          tlv(c.BSSID,MAC)+tlv(c.REQUEST_TYPE,b'\x03'),tlv(c.BSSID,MAC)+tlv(c.REQUEST_TYPE,bytes(4)),
          tlv(c.BSSID,MAC)+tlv(c.REQUEST_TYPE,struct.pack('<I',99))]
        for value in malformed:
            with self.assertRaises(c.CodecError):c.decode_request(value)
        for item in [c.Commit(19,b'',b'a'),c.Commit(65536,b'a',b'b'),c.Commit(19,b'a'*65536,b'b')]:
            with self.assertRaises(c.CodecError):c.encode_request(c.Request(MAC,0,item))

    def test_version_gates(self):
        with self.assertRaises(c.CodecError):c.encode_request(self.req,0x10107)
        request=c.Request(MAC,4,c.Commit(19,b'a',b'b',token=b'T',rejected_groups=b'\x14\0'))
        with self.assertRaises(c.CodecError):c.encode_request(request,0x10108)
        encoded=c.encode_request(request,0x1010a)
        with self.assertRaises(c.CodecError):c.decode_request(encoded,0x10108)
        self.assertEqual(c.decode_request(encoded,0x1010a),request)

    def test_missing_indication_content(self):
        for kind in (1,2,3):
            with self.assertRaises(c.CodecError):c.encode_indication(MAC,kind)
        with self.assertRaises(c.CodecError):c.encode_indication(MAC,1,commit_response=b'')

if __name__=='__main__':
    unittest.main(verbosity=2)
