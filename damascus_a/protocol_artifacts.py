"""Actual wire-byte accounting, separate from proof acceptance and transport.

The full-proof artifact is the canonical DF/proof/v1 object. Context (which
contains registration), certification and receipt objects are reported separately
and are never silently treated as free. Their sum is not a measured network cost.
"""

from hashlib import sha256

from .encoding import Reader
from .protocol_types import EpochContext, WireLimits
from .wire import decode_proof, encode_context, encode_registration


def _artifact(raw: bytes) -> dict:
    return {'bytes':len(raw),'sha256':sha256(raw).hexdigest(),'hex':raw.hex()}


def _optional_artifact(raw: bytes | None, limits: WireLimits) -> dict | None:
    if raw is None:return None
    if type(raw) is not bytes:raise TypeError('evidence artifact must be bytes or None')
    if not raw or len(raw)>limits.max_total_bytes:
        raise ValueError('evidence artifact is empty or exceeds resource limit')
    return _artifact(raw)


def serialization_evidence(context: EpochContext, proof_bytes: bytes, *,
                           epoch_evidence: bytes | None = None,
                           publication_evidence: bytes | None = None,
                           limits: WireLimits = WireLimits()) -> dict:
    """Validate wire, partition every byte, and retain actual external-object sizes.

    Algebra, codec legality, external certification and parameter security are
    deliberately not inferred from this accounting operation. Call the complete
    verifier separately and retain its result alongside this evidence.
    """
    proof=decode_proof(proof_bytes,context,limits=limits)
    outer=Reader(proof_bytes,max_total=limits.max_total_bytes)
    outer.blob(max_bytes=32)
    header_end=outer.offset+4
    payload=outer.blob(max_bytes=limits.max_blob_bytes);outer.finish()
    parts=[{'kind':'header','offset':0,'artifact':_artifact(proof_bytes[:header_end])}]
    r=Reader(payload,max_total=limits.max_blob_bytes)
    def append(kind,start,end):
        parts.append({'kind':kind,'offset':header_end+start,
                      'artifact':_artifact(payload[start:end])})
    start=r.offset;r.blob(max_bytes=32);append('context',start,r.offset)
    start=r.offset;count=r.uint(max_bytes=8);append('header',start,r.offset)
    assert count==len(proof.records)  # Established by canonical decoder above.
    for _ in range(count):
        start=r.offset;r.blob(max_bytes=limits.max_blob_bytes)
        append('round_record',start,r.offset)
    start=r.offset;r.sint(max_bytes=limits.max_integer_bytes)
    append('terminal_opening',start,r.offset);r.finish()
    registration=_artifact(encode_registration(context.registration,limits=limits))
    auxiliary={'context':_artifact(encode_context(context,limits=limits)),
               'epoch_evidence':_optional_artifact(epoch_evidence,limits),
               'publication_evidence':_optional_artifact(publication_evidence,limits)}
    return {'serialization':{'wire_profile':'DF-wire-v1',
                              'codec':'descriptor-hex:'+context.registration.pp.codec.hex(),
                              'full_proof':_artifact(proof_bytes),
                              'registration':registration,'parts':parts},
            'auxiliary_artifacts':auxiliary,
            'network_transfer_measured':False,'proof_acceptance_established':False,
            'byte_scope':('Full proof includes all framing, context digest, ordered records '
                          'and integer opening; round artifacts include their enclosing '
                          'length prefix. Full context and external evidence are separate '
                          'actual serialized objects. Context embeds registration; do not '
                          'interpret their sum as deduplicated network traffic.')}
