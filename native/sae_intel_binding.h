#ifndef SAE_INTEL_BINDING_H
#define SAE_INTEL_BINDING_H
#include "sae_session.h"
/* PINNED Netwtw06.sys 20.70.32.1 only, SHA256 615dbe4c...ff672ba1.
 * Bounded borrowed views, not a pointer validation/reference/lifetime API.
 * The integrating hook must guarantee objects are alive and immutable for
 * capture AND session begin in its actual serialized lifecycle domain.
 * Views may be original object bytes or stable copies; addresses are the
 * original driver addresses, not copy-buffer addresses. No address is followed.
 * Output may not overlap either view; an overlap error writes no output.
 */
typedef struct SaeIntelConnectIdentity {
 uint64_t port_interface,command,ndis_request;
 uint32_t transaction,ihv_specific,ndis_port;
 uint16_t wdi_port,reserved;
} SaeIntelConnectIdentity;
enum { SAE_INTEL_OK=0, SAE_INTEL_INVALID=1, SAE_INTEL_STALE=2,
       SAE_INTEL_UNSUPPORTED=3 };
SAE_API int sae_intel_capture_connect(uint64_t image_base,
 uint64_t port_address,const uint8_t *port_view,size_t port_length,
 uint64_t command_address,const uint8_t *command_view,size_t command_length,
 SaeIntelConnectIdentity *);
/* Caller-supplied generation is not derived from a reusable object pointer or
 * wrapping WDI transaction. Invoke only at a real fresh/cached auth boundary,
 * never merely because a CONNECT object has been allocated/parsed. Captured
 * identity is not an owned command reference and must not outlive that boundary.
 */
SAE_API int sae_intel_begin_captured_connect(SaeSession *,
 const SaeIntelConnectIdentity *,uint64_t generation,
 const uint8_t peer[6],const uint8_t local[6],int fresh,uint32_t *effects);
#endif
