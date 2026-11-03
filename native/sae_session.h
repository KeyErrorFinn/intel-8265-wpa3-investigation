#ifndef SAE_SESSION_H
#define SAE_SESSION_H
#include "sae_codec.h"
/* NEW caller-serialized integration component; not a recovered Intel layout.
 * Every operation, including callbacks, must hold the same external lock/run
 * in one serialized execution domain. No allocation, kernel API or atomics.
 * Generation assignment and mapping OS requests to a live connect task remain
 * the integrating driver's responsibility; an over-air frame carries no such
 * generation. Keep this storage alive until real transport quiescence, not
 * merely until property-command completion or scheduler admission shutdown.
 */
enum { SAE_SESSION_OK=0, SAE_SESSION_INVALID=1, SAE_SESSION_STALE=2,
       SAE_SESSION_BUSY=3, SAE_SESSION_NO_SLOT=4 };
enum { SAE_SESSION_IDLE=0, SAE_SESSION_ACTIVE=1, SAE_SESSION_VERIFIED=2,
       SAE_SESSION_ASSOC_READY=3, SAE_SESSION_FAILED=4, SAE_SESSION_CANCELED=5 };
enum { SAE_EFFECT_FORWARD_COMMIT=1, SAE_EFFECT_FORWARD_CONFIRM=2,
       SAE_EFFECT_ASSOCIATE=4, SAE_EFFECT_FAIL=8, SAE_EFFECT_REQUEST_COMMIT=16,
       SAE_EFFECT_BYPASS_CACHED=32 };
typedef struct SaeTxLease { uint64_t ticket; uint32_t body_length,kind; } SaeTxLease;
typedef struct SaeSession {
 uint64_t generation,next_ticket;
 uint32_t phase,connect_transaction,pending,fresh,peer_commit_seen,
          peer_confirm_seen,commit_submitted,confirm_submitted,association_emitted;
 uint16_t port,reserved;
 uint8_t peer[6],local[6];
 SaeTxLease leases[16];
} SaeSession;
SAE_API void sae_session_init(SaeSession *);
SAE_API int sae_session_begin(SaeSession *,uint64_t,uint16_t,uint32_t,
 const uint8_t[6],const uint8_t[6],int,uint32_t *);
/* A matching fresh SAE context consumes legacy AUTH/FLUSH events, even after
 * failure/cancel. STALE must be dropped, never passed to the old continuation.
 * Cached-PMKID/open-auth paths bypass this fresh-exchange gate explicitly. */
SAE_API int sae_session_legacy_gate(const SaeSession *,uint64_t,int *);
SAE_API int sae_session_rx(SaeSession *,uint64_t,const uint8_t[6],
 const uint8_t *,size_t,uint32_t *);
/* Reserve only after a complete body is encoded/owned. kind=1 commit,2 confirm.
 * Caller must fail/retire on submission failure. A callback may be dropped;
 * do not free this context on the assumption of exactly one callback. */
SAE_API int sae_session_reserve_tx(SaeSession *,uint64_t,uint32_t,uint32_t,uint64_t *);
/* Raw recovered Intel TX status: exactly 1 is success; 0 is not success. */
SAE_API int sae_session_tx_complete(SaeSession *,uint64_t,uint64_t,uint32_t,uint32_t *);
SAE_API int sae_session_os_result(SaeSession *,uint64_t,const uint8_t[6],int,uint32_t *);
SAE_API int sae_session_cancel(SaeSession *,uint64_t);
/* Only call after ALL relevant radio/packet/callback paths are quiescent.
 * The recovered scheduler marker alone is NOT evidence of radio quiescence.
 * Outstanding losses fail an active/verified exchange; cannot imply TX success. */
SAE_API int sae_session_transport_drained(SaeSession *,uint64_t,uint32_t *);
#endif
