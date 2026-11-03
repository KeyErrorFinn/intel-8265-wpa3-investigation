"""New native session component invariants; no claim of private hook installation.

These tests call compiled C and reorder delivery/cancel/drain to check gating.
All frames, generations and OS outcomes are synthetic; no crypto is verified.
"""
import ctypes as t,pathlib,sys,unittest,struct,json,itertools
ROOT=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT));import test_native as n
lib=n.lib
class Lease(t.Structure):_fields_=[('ticket',t.c_uint64),('length',t.c_uint32),('kind',t.c_uint32)]
class Session(t.Structure):
    _fields_=[('generation',t.c_uint64),('next_ticket',t.c_uint64),
      ('phase',t.c_uint32),('transaction',t.c_uint32),('pending',t.c_uint32),('fresh',t.c_uint32),
      ('commit_seen',t.c_uint32),('confirm_seen',t.c_uint32),('commit_sent',t.c_uint32),
      ('confirm_sent',t.c_uint32),('association',t.c_uint32),('port',t.c_uint16),('reserved',t.c_uint16),
      ('peer',t.c_ubyte*6),('local',t.c_ubyte*6),('leases',Lease*16)]
assert t.sizeof(Session)==328
S=t.POINTER(Session);U=t.c_uint64;P=t.c_void_p;E=t.POINTER(t.c_uint32)
for name,args in {
 'init':[S],'begin':[S,U,t.c_uint16,t.c_uint32,P,P,t.c_int,E],
 'legacy_gate':[S,U,t.POINTER(t.c_int)],'rx':[S,U,P,P,t.c_size_t,E],
 'reserve_tx':[S,U,t.c_uint32,t.c_uint32,t.POINTER(U)],
 'tx_complete':[S,U,U,t.c_uint32,E],'os_result':[S,U,P,t.c_int,E],
 'cancel':[S,U],'transport_drained':[S,U,E]}.items():
    fn=getattr(lib,'sae_session_'+name);fn.argtypes=args;fn.restype=None if name=='init' else t.c_int
PEER=bytes.fromhex('021122334455');LOCAL=bytes.fromhex('0266778899aa')
def begin(s,g=1,fresh=1):
    e=t.c_uint32();rc=lib.sae_session_begin(t.byref(s),g,4,123,PEER,LOCAL,fresh,t.byref(e));return rc,e.value
def reserve(s,kind=1,g=1):
    ticket=U();rc=lib.sae_session_reserve_tx(t.byref(s),g,kind,104 if kind==1 else 40,t.byref(ticket));return rc,ticket.value
def rx(s,transaction=1,status=0,g=1,peer=PEER):
    body=struct.pack('<HHH',3,transaction,status)+b'opaque';e=t.c_uint32()
    rc=lib.sae_session_rx(t.byref(s),g,peer,body,len(body),t.byref(e));return rc,e.value
def complete(s,ticket,status=1,g=1):
    e=t.c_uint32();rc=lib.sae_session_tx_complete(t.byref(s),g,ticket,status,t.byref(e));return rc,e.value
def os_result(s,success=1,g=1,peer=PEER):
    e=t.c_uint32();rc=lib.sae_session_os_result(t.byref(s),g,peer,success,t.byref(e));return rc,e.value
def prepared():
    s=Session();assert begin(s)==(0,16)
    _,commit=reserve(s);assert rx(s)==(0,1);_,confirm=reserve(s,2);assert rx(s,2)==(0,2)
    return s,commit,confirm
class SessionTests(unittest.TestCase):
    def test_fresh_begin_and_cached_explicit_bypass(self):
        for fresh,expected in ((1,16),(0,32)):
            s=Session();self.assertEqual(begin(s,fresh=fresh),(0,expected))
            consume=t.c_int();self.assertEqual(lib.sae_session_legacy_gate(t.byref(s),1,t.byref(consume)),0)
            self.assertEqual(consume.value,fresh)
            if not fresh:self.assertEqual(reserve(s)[0],1)
    def test_sae_commit_never_enables_association(self):
        for status in (0,76,77,126):
            s=Session();begin(s);_,ticket=reserve(s)
            self.assertEqual(rx(s,status=status),(0,1));self.assertEqual(complete(s,ticket),(0,0))
            self.assertEqual(s.association,0);self.assertEqual(os_result(s),(1,0))
    def test_all_success_tx_os_orderings(self):
        for order in itertools.permutations(('os','commit','confirm')):
            s,c,f=prepared();effects=[]
            for action in order:
                rc,e=os_result(s) if action=='os' else complete(s,c if action=='commit' else f)
                self.assertEqual(rc,0);effects.append(e)
            self.assertEqual(effects[-1],4);self.assertEqual(sum(e==4 for e in effects),1)
            self.assertEqual(s.phase,3);self.assertEqual(s.pending,0)
    def test_os_failure_never_associates_after_tx(self):
        s,c,f=prepared();self.assertEqual(os_result(s,0),(0,8))
        self.assertEqual(complete(s,c),(0,0));self.assertEqual(complete(s,f),(0,0));self.assertEqual(s.phase,4)
    def test_raw_intel_tx_status_zero_and_five_fail(self):
        for status in (0,5):
            s,c,f=prepared();self.assertEqual(os_result(s),(0,0))
            self.assertEqual(complete(s,c,status),(0,8));self.assertEqual(complete(s,f),(0,0));self.assertEqual(s.association,0)
    def test_duplicate_completion_is_stale(self):
        s=Session();begin(s);_,c=reserve(s);self.assertEqual(complete(s,c),(0,0))
        self.assertEqual(complete(s,c),(2,0));self.assertEqual(s.pending,0)
    def test_cancellation_quarantines_outstanding_context(self):
        s,c,f=prepared();self.assertEqual(lib.sae_session_cancel(t.byref(s),1),0)
        self.assertEqual(begin(s,2)[0],3);self.assertEqual(complete(s,c),(0,0))
        self.assertEqual(complete(s,f),(0,0));self.assertEqual(begin(s,2),(0,16))
        self.assertEqual(complete(s,c,g=1),(2,0));self.assertEqual(s.pending,0)
    def test_dropped_callbacks_require_explicit_transport_quiescence(self):
        s,c,f=prepared();lib.sae_session_cancel(t.byref(s),1);self.assertEqual(begin(s,2)[0],3)
        e=t.c_uint32();self.assertEqual(lib.sae_session_transport_drained(t.byref(s),1,t.byref(e)),0)
        self.assertEqual((e.value,s.pending),(0,0));self.assertEqual(begin(s,2),(0,16))
    def test_active_drain_is_not_tx_success(self):
        s,c,f=prepared();os_result(s);e=t.c_uint32()
        self.assertEqual(lib.sae_session_transport_drained(t.byref(s),1,t.byref(e)),0)
        self.assertEqual((e.value,s.phase,s.association),(8,4,0))
    def test_stale_generation_and_foreign_peer_do_not_mutate(self):
        s,c,f=prepared();before=bytes(s)
        for result in (rx(s,g=2),rx(s,peer=LOCAL),os_result(s,g=2),os_result(s,peer=LOCAL),complete(s,c,g=2)):
            self.assertEqual(result,(2,0));self.assertEqual(bytes(s),before)
    def test_no_generation_reuse_or_ticket_reuse(self):
        s=Session();begin(s);_,old=reserve(s);complete(s,old);lib.sae_session_cancel(t.byref(s),1)
        self.assertEqual(begin(s,1)[0],2);self.assertEqual(begin(s,2),(0,16));_,new=reserve(s,g=2)
        self.assertGreater(new,old);self.assertEqual(complete(s,old,g=2),(2,0))
    def test_confirm_requires_local_commit_and_peer_commit(self):
        s=Session();begin(s);self.assertEqual(reserve(s,2)[0],1)
        rx(s);self.assertEqual(reserve(s,2)[0],1);reserve(s);self.assertEqual(reserve(s,2)[0],0)
    def test_capacity_and_ticket_exhaustion(self):
        s=Session();begin(s)
        for _ in range(16):self.assertEqual(reserve(s)[0],0)
        self.assertEqual(reserve(s)[0],4);self.assertEqual(s.pending,16)
        s=Session();begin(s);s.next_ticket=0xffffffffffffffff;self.assertEqual(reserve(s)[0],1)
    def test_canceled_legacy_events_remain_consumed(self):
        s=Session();begin(s);lib.sae_session_cancel(t.byref(s),1);c=t.c_int()
        self.assertEqual(lib.sae_session_legacy_gate(t.byref(s),1,t.byref(c)),0);self.assertEqual(c.value,1)
    def test_invalid_peer_addresses(self):
        for peer in (bytes(6),b'\xff'*6,LOCAL):
            s=Session();e=t.c_uint32()
            self.assertEqual(lib.sae_session_begin(t.byref(s),1,0,1,peer,LOCAL,1,t.byref(e)),1)
if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(SessionTests))
    name='session-nocrt-results.json' if '--no-crt' in sys.argv else 'session-results.json'
    (ROOT/name).write_text(json.dumps({'tests':result.testsRun,'success':result.wasSuccessful(),'dll':n.DLL.name,
      'scope':'New native caller-serialized session component; no original private hook installed, kernel/radio operation or cryptographic validation'}))
    sys.exit(not result.wasSuccessful())
