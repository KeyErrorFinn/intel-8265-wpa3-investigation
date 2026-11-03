#ifndef SAE_CODEC_H
#define SAE_CODEC_H
#include <stddef.h>
#include <stdint.h>
#ifdef _WIN32
#define SAE_API __declspec(dllexport)
#else
#define SAE_API
#endif
#ifdef __cplusplus
extern "C" {
#endif
enum { SAE_OK=0, SAE_INVALID=1, SAE_BUFFER_SMALL=2, SAE_VERSION=3 };
enum { SAE_NO_FRAME=4, SAE_UNSUPPORTED=5 };
enum { SAE_HAS_COMMIT=1, SAE_HAS_CONFIRM=2, SAE_HAS_STATUS=4 };
typedef struct SaeBlob { uint32_t offset, length; } SaeBlob;
typedef struct SaeRequest {
    uint8_t bssid[6]; uint16_t group;
    uint32_t request_type, status, flags;
    uint16_t send_confirm, reserved;
    SaeBlob scalar, element, token, rejected_groups, confirm;
    size_t owned_length;
} SaeRequest;
typedef struct SaeIndication {
    uint8_t bssid[6]; uint16_t reserved;
    uint32_t indication_type, status, flags;
    const uint8_t *commit_response; size_t commit_length;
    const uint8_t *confirm_response; size_t confirm_length;
} SaeIndication;
/* Payload only; caller owns the buffer and request. Input and owned storage
 * must not overlap the output request structure. Owned storage may overlap
 * input. All blob offsets refer to owned storage, never borrowed input.
 * On parse failure the copied bytes and output structure are erased.
 * No allocation, asynchronous state, kernel APIs or transport operations. */
SAE_API int sae_parse_request(const uint8_t *,size_t,uint32_t,
    uint8_t *,size_t,SaeRequest *);
SAE_API void sae_release_request(uint8_t *,size_t,SaeRequest *);
/* Reports required size without writing when output is null/too small.
 * Source blobs must remain valid during the call and not overlap output.
 * Returns an owned caller-buffer payload; caller wraps the WDI header. */
SAE_API int sae_encode_indication(const SaeIndication *,uint32_t,
    uint8_t *,size_t,size_t *);
/* Exact dot11wdi.h WDI_MESSAGE_HEADER layout; correlation values supplied by
 * caller, never inferred. 16 bytes; PortId/Reserved/Status/TransactionId/IhvId. */
SAE_API int sae_write_header(uint8_t *,size_t,uint16_t,uint32_t,uint32_t,uint32_t);
/* Receive-side wire adapter for the recovered authentication BODY view.
 * Requires algorithm 3, transaction 1/2 and the six-byte fixed body. Preserves
 * status and all variable bytes for Windows to validate. Caller supplies an
 * already-correlated peer BSSID and owns connection/port/lifetime checks.
 * Does not validate SAE cryptography, authenticate a peer or submit NDIS. */
SAE_API int sae_encode_auth_body_indication(const uint8_t[6],const uint8_t *,
    size_t,uint32_t,uint8_t *,size_t,size_t *);
/* Synchronous adapter for the recovered Netwtw06 20.70.32.1 x64 event-af
 * parsed object (0x5d0 bytes), NOT a public Intel ABI. Caller must own readable
 * parsed/header/body storage throughout this call and supply a current,
 * already-correlated connection's peer BSSID and local station address.
 * Checks header addresses and exact body-pointer relationship, ignoring the
 * legacy IE-parser success flag. No state transition, indication submission,
 * generation check, memory probing or ownership extension is performed. */
SAE_API int sae_encode_intel_rx_indication(const void *,size_t,
    const uint8_t[6],const uint8_t[6],uint32_t,uint8_t *,size_t,size_t *);
/* Encode an authentication BODY from an owned OS request. Does not derive or
 * validate cryptography. Supports classic SAE ECC groups 19/20/21 (not extended
 * key SAE, password identifiers, SAE-PK or FFC groups). Commit/confirm wire
 * order follows upstream hostap; scalar/element/confirm bytes stay opaque.
 * H2E rejected-group/token elements are bounded by their one-byte IE lengths.
 * Failure/success commands return SAE_NO_FRAME: they are local state actions.
 * No input/output overlap allowed. Caller owns the result; no radio submission,
 * connection transition, retry-counter increment, MAC header or FCS is added. */
SAE_API int sae_encode_tx_auth_body(const SaeRequest *,const uint8_t *,size_t,
    uint8_t *,size_t,size_t *);
/* NEW narrow association-IE writer, not the Intel association hook. Classic
 * SAE AKM8, CCMP-128 group/pairwise, PMF required, BIP-CMAC-128. Optional one
 * 16-byte PMKID and optional SAE-H2E RSNXE. Caller must negotiate this exact
 * profile, supply the correct OS PMKID, avoid duplicate IEs, and integrate key
 * installation/association ownership. Does not derive/cache keys or PMKIDs. */
SAE_API int sae_encode_ccmp_assoc_ies(const uint8_t *,size_t,int,
    uint8_t *,size_t,size_t *);
#ifdef __cplusplus
}
#endif
#endif
