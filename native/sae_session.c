#include "sae_session.h"
#include "sae_intel_binding.h"
_Static_assert(sizeof(SaeSession)==328,"Unexpected session ABI");
static void zero(void *p,size_t n) { uint8_t *s=p;while(n--)*s++=0; }
static int same(const uint8_t *a,const uint8_t *b,size_t n) {
 uint8_t diff=0;while(n--)diff|=*a++^*b++;return diff==0;
}
static int current(const SaeSession *s,uint64_t g) {
 return s&&g&&s->generation==g&&s->phase!=SAE_SESSION_IDLE;
}
static int unicast(const uint8_t *a) {
 static const uint8_t empty[6]={0};return a&&!(a[0]&1)&&!same(a,empty,6);
}
static uint64_t intel_le(const uint8_t *p,size_t n) {
 uint64_t v=0;size_t i;for(i=0;i<n;i++)v|=(uint64_t)p[i]<<(i*8);return v;
}
static int intel_overlap(const void *a,size_t an,const void *b,size_t bn) {
 uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
 return an&&bn&&(x<=y?y-x<an:x-y<bn);
}
SAE_API int sae_intel_capture_connect(uint64_t image,uint64_t port,
 const uint8_t *pv,size_t pn,uint64_t command,const uint8_t *cv,size_t cn,
 SaeIntelConnectIdentity *out) {
 uint64_t vt;SaeIntelConnectIdentity identity;
 if(!out)return SAE_INTEL_INVALID;
 if((pv&&intel_overlap(out,sizeof(*out),pv,pn))||
    (cv&&intel_overlap(out,sizeof(*out),cv,cn)))return SAE_INTEL_INVALID;
 zero(out,sizeof(*out));
 if(!pv||!cv||pn<0xc0||cn<0x9c||!port||!command||!image||
    image>UINT64_MAX-0x493360)return SAE_INTEL_INVALID;
 vt=intel_le(pv,8);
 if((vt!=image+0x49a160&&vt!=image+0x49a7d0)||
    intel_le(cv,8)!=image+0x493360||intel_le(cv+0x10,4)!=0xe4400006)
  return SAE_INTEL_UNSUPPORTED;
 if(intel_le(pv+0xb8,8)!=command||intel_le(cv+8,8)!=port)return SAE_INTEL_STALE;
 /* +0x60 marks completed OID, not ended task. Original completeOid(0)
  * retains an asynchronous task after setting it. Destruction can also begin
  * while the same slot/vtable still appears live: caller owns lifetime proof. */
 zero(&identity,sizeof(identity));
 identity.port_interface=port;identity.command=command;
 identity.ndis_request=intel_le(cv+0x48,8);
 identity.ndis_port=(uint32_t)intel_le(cv+0x44,4);
 identity.wdi_port=(uint16_t)intel_le(cv+0x8c,2);
 identity.transaction=(uint32_t)intel_le(cv+0x94,4);
 identity.ihv_specific=(uint32_t)intel_le(cv+0x98,4);
 if(!identity.ndis_request||identity.ndis_port!=identity.wdi_port||
    intel_le(cv+0x8e,2)!=0)return SAE_INTEL_INVALID;
 *out=identity;return SAE_INTEL_OK;
}
SAE_API int sae_intel_begin_captured_connect(SaeSession *s,
 const SaeIntelConnectIdentity *identity,uint64_t generation,
 const uint8_t peer[6],const uint8_t local[6],int fresh,uint32_t *effects) {
 if(effects)*effects=0;
 if(!identity||!identity->port_interface||!identity->command||
    !identity->ndis_request||identity->ndis_port!=identity->wdi_port||
    identity->reserved)return SAE_SESSION_INVALID;
 return sae_session_begin(s,generation,identity->wdi_port,identity->transaction,
                          peer,local,fresh,effects);
}
static void ready(SaeSession *s,uint32_t *effects) {
 if(s->phase==SAE_SESSION_VERIFIED&&!s->pending&&!s->association_emitted) {
  s->association_emitted=1;s->phase=SAE_SESSION_ASSOC_READY;*effects|=SAE_EFFECT_ASSOCIATE;
 }
}
SAE_API void sae_session_init(SaeSession *s) { if(s)zero(s,sizeof(*s)); }
SAE_API int sae_session_begin(SaeSession *s,uint64_t g,uint16_t port,uint32_t transaction,
 const uint8_t peer[6],const uint8_t local[6],int fresh,uint32_t *effects) {
 size_t i;uint64_t next;
 if(!s||!effects||!g||!unicast(peer)||!unicast(local)||same(peer,local,6))return SAE_SESSION_INVALID;
 *effects=0;
 if(g<=s->generation)return SAE_SESSION_STALE;
 if(s->pending||s->phase==SAE_SESSION_ACTIVE||s->phase==SAE_SESSION_VERIFIED)return SAE_SESSION_BUSY;
 next=s->next_ticket;zero(s,sizeof(*s));s->next_ticket=next;s->generation=g;
 s->port=port;s->connect_transaction=transaction;s->phase=SAE_SESSION_ACTIVE;s->fresh=fresh!=0;
 for(i=0;i<6;i++){s->peer[i]=peer[i];s->local[i]=local[i];}
 *effects=s->fresh?SAE_EFFECT_REQUEST_COMMIT:SAE_EFFECT_BYPASS_CACHED;return SAE_SESSION_OK;
}
SAE_API int sae_session_legacy_gate(const SaeSession *s,uint64_t g,int *consume) {
 if(!consume)return SAE_SESSION_INVALID;*consume=0;
 if(!current(s,g))return SAE_SESSION_STALE;
 *consume=s->fresh!=0;return SAE_SESSION_OK;
}
SAE_API int sae_session_rx(SaeSession *s,uint64_t g,const uint8_t peer[6],
 const uint8_t *body,size_t n,uint32_t *effects) {
 uint16_t txn;
 if(!effects)return SAE_SESSION_INVALID;*effects=0;
 if(!current(s,g)||!peer||!same(s->peer,peer,6))return SAE_SESSION_STALE;
 if(!s->fresh||s->phase!=SAE_SESSION_ACTIVE||!body||n<6||n>65535||body[0]!=3||body[1])return SAE_SESSION_INVALID;
 txn=(uint16_t)(body[2]|((uint16_t)body[3]<<8));
 if(txn==1){s->peer_commit_seen=1;*effects=SAE_EFFECT_FORWARD_COMMIT;return SAE_SESSION_OK;}
 if(txn==2&&s->confirm_submitted){s->peer_confirm_seen=1;*effects=SAE_EFFECT_FORWARD_CONFIRM;return SAE_SESSION_OK;}
 return SAE_SESSION_INVALID;
}
SAE_API int sae_session_reserve_tx(SaeSession *s,uint64_t g,uint32_t kind,uint32_t n,uint64_t *ticket) {
 size_t i;
 if(!ticket)return SAE_SESSION_INVALID;*ticket=0;
 if(!current(s,g))return SAE_SESSION_STALE;
 if(!s->fresh||s->phase!=SAE_SESSION_ACTIVE||n<6||n>65535||
    (kind!=1&&kind!=2)||(kind==2&&(!s->peer_commit_seen||!s->commit_submitted))||s->next_ticket==UINT64_MAX)return SAE_SESSION_INVALID;
 for(i=0;i<16;i++)if(!s->leases[i].ticket) {
  s->leases[i].ticket=++s->next_ticket;s->leases[i].body_length=n;s->leases[i].kind=kind;
  s->pending++;if(kind==2)s->confirm_submitted=1;else s->commit_submitted=1;
  *ticket=s->leases[i].ticket;return SAE_SESSION_OK;
 }
 return SAE_SESSION_NO_SLOT;
}
SAE_API int sae_session_tx_complete(SaeSession *s,uint64_t g,uint64_t ticket,uint32_t status,uint32_t *effects) {
 size_t i;
 if(!effects)return SAE_SESSION_INVALID;*effects=0;
 if(!current(s,g))return SAE_SESSION_STALE;
 for(i=0;i<16;i++)if(ticket&&s->leases[i].ticket==ticket) {
  zero(&s->leases[i],sizeof(s->leases[i]));s->pending--;
  if(status!=1&&(s->phase==SAE_SESSION_ACTIVE||s->phase==SAE_SESSION_VERIFIED)) {
   s->phase=SAE_SESSION_FAILED;*effects=SAE_EFFECT_FAIL;
  } else ready(s,effects);
  return SAE_SESSION_OK;
 }
 return SAE_SESSION_STALE;
}
SAE_API int sae_session_os_result(SaeSession *s,uint64_t g,const uint8_t peer[6],int success,uint32_t *effects) {
 if(!effects)return SAE_SESSION_INVALID;*effects=0;
 if(!current(s,g)||!peer||!same(s->peer,peer,6))return SAE_SESSION_STALE;
 if(!s->fresh||s->phase!=SAE_SESSION_ACTIVE)return SAE_SESSION_INVALID;
 if(!success){s->phase=SAE_SESSION_FAILED;*effects=SAE_EFFECT_FAIL;return SAE_SESSION_OK;}
 if(!s->peer_confirm_seen||!s->confirm_submitted)return SAE_SESSION_INVALID;
 s->phase=SAE_SESSION_VERIFIED;ready(s,effects);return SAE_SESSION_OK;
}
SAE_API int sae_session_cancel(SaeSession *s,uint64_t g) {
 if(!current(s,g))return SAE_SESSION_STALE;s->phase=SAE_SESSION_CANCELED;return SAE_SESSION_OK;
}
SAE_API int sae_session_transport_drained(SaeSession *s,uint64_t g,uint32_t *effects) {
 if(!effects)return SAE_SESSION_INVALID;*effects=0;
 if(!current(s,g))return SAE_SESSION_STALE;
 if(s->pending&&(s->phase==SAE_SESSION_ACTIVE||s->phase==SAE_SESSION_VERIFIED)) {
  s->phase=SAE_SESSION_FAILED;*effects=SAE_EFFECT_FAIL;
 }
 zero(s->leases,sizeof(s->leases));s->pending=0;return SAE_SESSION_OK;
}
