"""Owned SAE WDI TLV codec derived from Microsoft's WABIModel.xml.

This is a real wire-format reference component, not a Windows driver, SAE
cryptography, or exchange simulator. APIs consume/produce TLV PAYLOADS ONLY:
the caller handles the 16-byte WDI header, port/task correlation and transport.
All decoded blobs are immutable owned copies, safe after the input buffer is
released or mutated. There are no asynchronous callbacks or mutable sessions.
"""
from dataclasses import dataclass
import struct

BSSID=0x2
INDICATION_TYPE=0x14b; STATUS=0x14c; COMMIT_RESPONSE=0x14d; CONFIRM_RESPONSE=0x14e
REQUEST_TYPE=0x14f; COMMIT_REQUEST=0x150; CONFIRM_REQUEST=0x151
GROUP=0x152; SCALAR=0x153; ELEMENT=0x154; TOKEN=0x155
SEND_CONFIRM=0x156; CONFIRM=0x157; REJECTED_GROUPS=0x16f
SAE_VERSION=0x10108; REJECTED_GROUPS_VERSION=0x1010a; CURRENT_VERSION=0x1010c

class CodecError(ValueError):pass

def _version(version):
    if version<SAE_VERSION:raise CodecError('SAE requires WDI 1.1.8 or later')

def _blob(value):
    out=memoryview(value).tobytes()
    if not out:raise CodecError('ByteBlob must contain at least one byte')
    if len(out)>0xffff:raise CodecError('TLV length exceeds UINT16')
    return out

def _mac(value):
    out=memoryview(value).tobytes()
    if len(out)!=6:raise CodecError('BSSID must be six bytes')
    return out

def _uint(value,size):
    if not isinstance(value,int) or not 0<=value<(1<<(size*8)):raise CodecError('integer out of range')
    return value.to_bytes(size,'little')

def _decode_uint(value,size):
    if len(value)!=size:raise CodecError('incorrect integer TLV length')
    return int.from_bytes(value,'little')

def _tlv(kind,value):
    value=memoryview(value).tobytes()
    if len(value)>0xffff:raise CodecError('TLV length exceeds UINT16')
    return struct.pack('<HH',kind,len(value))+value

def _fields(payload,known):
    # Copy the entire borrowed input first; slices therefore cannot retain a
    # pointer into a request buffer that original CCmd completion can release.
    payload=memoryview(payload).tobytes();pos=0;out={}
    while pos<len(payload):
        if len(payload)-pos<4:raise CodecError('truncated TLV header')
        kind,n=struct.unpack_from('<HH',payload,pos);pos+=4
        if n>len(payload)-pos:raise CodecError('truncated TLV value')
        value=payload[pos:pos+n];pos+=n
        if kind in known:
            if kind in out:raise CodecError('duplicate singleton TLV')
            out[kind]=value
        # Unknown IDs are skipped, preserving WDI forward compatibility.
    return out

def _required(fields,kind):
    if kind not in fields:raise CodecError(f'missing required TLV {kind:#x}')
    return fields[kind]

@dataclass(frozen=True)
class Commit:
    group:int
    scalar:bytes
    element:bytes
    token:bytes|None=None
    rejected_groups:bytes|None=None

@dataclass(frozen=True)
class Confirmation:
    send_confirm:int
    confirm:bytes

@dataclass(frozen=True)
class Request:
    bssid:bytes
    request_type:int
    commit:Commit|None=None
    confirmation:Confirmation|None=None
    status:int|None=None

def _commit_encode(commit,version):
    value=_tlv(GROUP,_uint(commit.group,2))+_tlv(SCALAR,_blob(commit.scalar))+_tlv(ELEMENT,_blob(commit.element))
    if commit.token is not None:value+=_tlv(TOKEN,_blob(commit.token))
    if commit.rejected_groups is not None:
        if version<REJECTED_GROUPS_VERSION:raise CodecError('RejectedGroups requires WDI 1.1.10')
        value+=_tlv(REJECTED_GROUPS,_blob(commit.rejected_groups))
    return value

def _coherent(request,version):
    # Requirements follow Microsoft's request-type enum; optional fields in the
    # XML remain optional for unrelated request types rather than inventing a
    # stricter command-state policy here.
    kind=request.request_type
    if kind not in range(5):raise CodecError('unknown SAE request type')
    if kind in (0,4) and request.commit is None:raise CodecError('commit parameters required')
    if kind==1 and request.confirmation is None:raise CodecError('confirm parameters required')
    if kind==2 and request.status is None:raise CodecError('failure status required')

def encode_request(request,version=CURRENT_VERSION):
    _version(version);_coherent(request,version)
    value=_tlv(BSSID,_mac(request.bssid))+_tlv(REQUEST_TYPE,_uint(request.request_type,4))
    if request.commit is not None:value+=_tlv(COMMIT_REQUEST,_commit_encode(request.commit,version))
    if request.confirmation is not None:
        item=request.confirmation
        value+=_tlv(CONFIRM_REQUEST,_tlv(SEND_CONFIRM,_uint(item.send_confirm,2))+_tlv(CONFIRM,_blob(item.confirm)))
    if request.status is not None:value+=_tlv(STATUS,_uint(request.status,4))
    return value

def decode_request(payload,version=CURRENT_VERSION):
    _version(version)
    fields=_fields(payload,{BSSID,REQUEST_TYPE,COMMIT_REQUEST,CONFIRM_REQUEST,STATUS})
    bssid=_mac(_required(fields,BSSID));kind=_decode_uint(_required(fields,REQUEST_TYPE),4)
    commit=None;confirmation=None
    if COMMIT_REQUEST in fields:
        f=_fields(fields[COMMIT_REQUEST],{GROUP,SCALAR,ELEMENT,TOKEN,REJECTED_GROUPS})
        if REJECTED_GROUPS in f and version<REJECTED_GROUPS_VERSION:raise CodecError('RejectedGroups requires WDI 1.1.10')
        commit=Commit(_decode_uint(_required(f,GROUP),2),_blob(_required(f,SCALAR)),_blob(_required(f,ELEMENT)),
          _blob(f[TOKEN]) if TOKEN in f else None,_blob(f[REJECTED_GROUPS]) if REJECTED_GROUPS in f else None)
    if CONFIRM_REQUEST in fields:
        f=_fields(fields[CONFIRM_REQUEST],{SEND_CONFIRM,CONFIRM})
        confirmation=Confirmation(_decode_uint(_required(f,SEND_CONFIRM),2),_blob(_required(f,CONFIRM)))
    result=Request(bssid,kind,commit,confirmation,_decode_uint(fields[STATUS],4) if STATUS in fields else None)
    _coherent(result,version);return result

def encode_indication(bssid,indication_type,*,commit_response=None,confirm_response=None,status=None,version=CURRENT_VERSION):
    """Encode a real SAE indication TLV payload; response frame bytes are opaque.

    Response bytes are the authentication BODY without the MAC header, as
    confirmed by original Windows WDI-to-native translation and prefix checks.
    This generic encoder leaves structural validation to the receive adapter.
    No scalar generation, peer validation or success inference is performed.
    """
    _version(version)
    if indication_type not in range(5):raise CodecError('unknown SAE indication type')
    if indication_type==1 and commit_response is None:raise CodecError('commit response required')
    if indication_type==2 and confirm_response is None:raise CodecError('confirm response required')
    if indication_type==3 and status is None:raise CodecError('error status required')
    value=_tlv(BSSID,_mac(bssid))+_tlv(INDICATION_TYPE,_uint(indication_type,4))
    if commit_response is not None:value+=_tlv(COMMIT_RESPONSE,_blob(commit_response))
    if confirm_response is not None:value+=_tlv(CONFIRM_RESPONSE,_blob(confirm_response))
    if status is not None:value+=_tlv(STATUS,_uint(status,4))
    return value
