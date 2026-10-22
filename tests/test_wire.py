import importlib
import importlib.util
import unittest
from dataclasses import FrozenInstanceError, replace

from damascus_a.algebra import Ring
from damascus_a.encoding import DecodeError, Reader, encode_bytes, encode_sint, encode_uint, frame, read_frame
from damascus_a.fold import FoldParameters, PublicState, RoundRecord


class WireTests(unittest.TestCase):
    def api(self):
        self.assertIsNotNone(importlib.util.find_spec('damascus_a.wire'),
                             'typed canonical protocol wire is not implemented')
        return (importlib.import_module('damascus_a.protocol_types'),
                importlib.import_module('damascus_a.wire'))

    def fixture(self):
        types, wire = self.api()
        arithmetic = FoldParameters(d=2, T=4, k=2, q=257)
        ring = Ring(257, 4)
        generators = tuple(tuple(ring.element(tuple((i+j+c+1) % 257 for c in range(4)))
                                 for j in range(2)) for i in range(4))
        initial = PublicState(arithmetic, 0, generators, (ring.zero(), ring.zero()))
        pp = types.ProtocolParameters(arithmetic, b'explicit-test-codec')
        reg = types.Registration(pp, b'file-identity', 9, initial)
        ctx = types.EpochContext(reg, b'epoch-7', b'public-seed', b'provider-order:12')
        records = []
        for j in range(2):
            current, child = Ring(257, 4 >> j), Ring(257, 2 >> j)
            records.append(RoundRecord((current.zero(),)*2, (current.zero(),)*2,
                                       (child.zero(),)*2, (child.zero(),)*2))
        proof = types.EpochProof(wire.context_binding(ctx), tuple(records), -(2**300))
        return types, wire, pp, reg, ctx, proof

    def test_immutable_typed_objects_and_roundtrip_all_objects(self):
        types, wire, pp, reg, ctx, proof = self.fixture()
        pairs = [(wire.encode_pp, wire.decode_pp, pp),
                 (wire.encode_registration, wire.decode_registration, reg),
                 (wire.encode_context, wire.decode_context, ctx)]
        for encode, decode, value in pairs:
            with self.subTest(type=type(value).__name__):
                raw = encode(value)
                self.assertEqual(decode(raw), value)
                self.assertEqual(encode(decode(raw)), raw)
        for j, record in enumerate(proof.records):
            raw = wire.encode_round_record(record, j, pp)
            self.assertEqual(wire.decode_round_record(raw, j, pp), record)
            self.assertEqual(wire.encode_round_record(wire.decode_round_record(raw,j,pp),j,pp),raw)
        raw = wire.encode_proof(proof, ctx)
        self.assertEqual(wire.decode_proof(raw, ctx), proof)
        self.assertEqual(wire.encode_proof(wire.decode_proof(raw,ctx),ctx),raw)
        with self.assertRaises(FrozenInstanceError):
            ctx.seed = b'changed'

    def test_type_validation_rejects_ambiguous_values_and_wrong_initial_state(self):
        types, wire, pp, reg, ctx, proof = self.fixture()
        for bad in (b'', bytearray(b'x'), 'text', True):
            with self.subTest(bad=bad):
                with self.assertRaises((TypeError, ValueError)):
                    types.ProtocolParameters(pp.arithmetic, bad)
                with self.assertRaises((TypeError, ValueError)):
                    replace(ctx, deadline=bad)
        with self.assertRaises((TypeError, ValueError)):
            replace(reg, file_length=True)
        with self.assertRaises((TypeError, ValueError)):
            replace(reg, file_length=-1)
        with self.assertRaises((TypeError, ValueError)):
            replace(proof, records=list(proof.records))
        with self.assertRaises((TypeError, ValueError)):
            replace(proof, opening=True)
        with self.assertRaises((TypeError, ValueError)):
            replace(proof, context_digest=b'x')
        with self.assertRaises(ValueError):
            replace(reg, pp=replace(pp, arithmetic=replace(pp.arithmetic,T=8)))

    def test_parameter_wire_exact_vector_and_nonminimal_integer(self):
        _, wire, pp, _, _, _ = self.fixture()
        payload = (encode_uint(257)+encode_uint(2)+encode_uint(2)+encode_uint(4)
                   +encode_bytes(pp.codec)+encode_bytes(pp.suite))
        self.assertEqual(wire.encode_pp(pp),frame(b'DF/pp/v1',payload))
        nonminimal_q = encode_bytes(b'\0\1\1') + payload[len(encode_uint(257)):]
        with self.assertRaises(DecodeError):
            wire.decode_pp(frame(b'DF/pp/v1',nonminimal_q))
        with self.assertRaises(DecodeError):
            wire.decode_pp(frame(b'DF/other/v1',payload))

    def test_context_binding_covers_all_public_fields_and_generators(self):
        _, wire, pp, reg, ctx, _ = self.fixture()
        baseline=wire.context_binding(ctx)
        mutations=[replace(ctx,epoch=b'another'), replace(ctx,seed=b'another'),
                   replace(ctx,deadline=b'another'),
                   replace(ctx,registration=replace(reg,file_id=b'another')),
                   replace(ctx,registration=replace(reg,file_length=10)),
                   replace(ctx,registration=replace(reg,pp=replace(pp,codec=b'another'))),
                   replace(ctx,registration=replace(reg,pp=replace(pp,suite=b'another')))]
        first=reg.initial.generators[0]
        changed=(first[0]+first[0].ring.element((1,0,0,0)),first[1])
        initial=replace(reg.initial,generators=(changed,)+reg.initial.generators[1:])
        mutations.append(replace(ctx,registration=replace(reg,initial=initial)))
        for mutated in mutations:
            self.assertNotEqual(wire.context_binding(mutated),baseline)

    def test_proof_is_context_bound_and_does_not_repeat_registration(self):
        _, wire, _, reg, ctx, proof = self.fixture()
        raw=wire.encode_proof(proof,ctx)
        self.assertNotIn(wire.encode_registration(reg),raw)
        with self.assertRaises(DecodeError):
            wire.decode_proof(raw,replace(ctx,seed=b'wrong'))
        with self.assertRaises((ValueError,DecodeError)):
            wire.encode_proof(replace(proof,context_digest=b'\xff'*32),ctx)

    def test_exact_round_count_and_order_and_missing_opening(self):
        _, wire, pp, _, ctx, proof = self.fixture()
        for records in (proof.records[:-1],proof.records+proof.records[:1],proof.records[::-1]):
            with self.assertRaises((ValueError,DecodeError)):
                wire.encode_proof(replace(proof,records=records),ctx)
        for count in (0,1,3,2**63):
            payload=encode_bytes(proof.context_digest)+encode_uint(count)
            with self.assertRaises(DecodeError):
                wire.decode_proof(frame(b'DF/proof/v1',payload),ctx)
        raw=wire.encode_round_record(proof.records[0],0,pp)
        with self.assertRaises(DecodeError):
            wire.decode_round_record(raw,1,pp)
        encoded=wire.encode_proof(proof,ctx)
        tag,payload=read_frame(encoded)
        opening=encode_sint(proof.opening)
        with self.assertRaises(DecodeError):
            wire.decode_proof(frame(tag,payload[:-len(opening)]),ctx)

    def test_truncation_trailing_bytes_bad_domain_and_negative_zero(self):
        _, wire, _, _, ctx, proof=self.fixture()
        raw=wire.encode_proof(proof,ctx)
        for end in range(len(raw)):
            with self.subTest(end=end):
                with self.assertRaises(DecodeError):
                    wire.decode_proof(raw[:end],ctx)
        with self.assertRaises(DecodeError):
            wire.decode_proof(raw+b'x',ctx)
        tag,payload=read_frame(raw)
        with self.assertRaises(DecodeError):
            wire.decode_proof(frame(b'DF/context/v1',payload),ctx)
        opening=encode_sint(proof.opening)
        for malformed in (b'\1'+encode_uint(0),b'\2'+encode_uint(1),
                          b'\0'+encode_bytes(b'\0\1')):
            with self.assertRaises(DecodeError):
                wire.decode_proof(frame(tag,payload[:-len(opening)]+malformed),ctx)

    def test_full_module_coordinates_and_noncanonical_residue_rejected(self):
        _, wire, pp, _, _, proof=self.fixture()
        record=proof.records[0]
        raw=wire.encode_round_record(record,0,pp)
        tag,payload=read_frame(raw)
        r=Reader(payload); index=r.uint(); module=r.blob()
        suffix=payload[r.offset:]
        mr=Reader(module); self.assertEqual(mr.uint(),2); self.assertEqual(mr.uint(),4)
        coefficients=module[mr.offset:]
        self.assertEqual(len(coefficients),2*4*2)
        alias=module[:mr.offset]+(257).to_bytes(2,'big')+coefficients[2:]
        with self.assertRaises(DecodeError):
            wire.decode_round_record(frame(tag,encode_uint(index)+encode_bytes(alias)+suffix),0,pp)
        bad_count=encode_uint(2**63)+module[len(encode_uint(2)):]
        with self.assertRaises(DecodeError):
            wire.decode_round_record(frame(tag,encode_uint(index)+encode_bytes(bad_count)+suffix),0,pp)
        standalone=wire.encode_module(record.L_vec)
        mtag,mpayload=read_frame(standalone)
        self.assertEqual(mtag,b'DF/module/v1')
        mr=Reader(mpayload); self.assertEqual(mr.uint(),257)
        self.assertEqual(mr.uint(),4); self.assertEqual(mr.uint(),2)

    def test_zero_round_empty_file_and_integer_opening_boundaries(self):
        types, wire = self.api()
        arithmetic = FoldParameters(d=0, T=4, k=1, q=257)
        ring = Ring(257, 1)
        initial = PublicState(arithmetic, 0, ((ring.element((7,)),),), (ring.zero(),))
        pp = types.ProtocolParameters(arithmetic, b'explicit-test-codec')
        registration = types.Registration(pp, b'empty-file', 0, initial)
        context = types.EpochContext(registration, b'epoch', b'seed', b'deadline')
        for opening in (0, -1, 1, -(2**521), 2**521):
            proof = types.EpochProof(wire.context_binding(context), (), opening)
            self.assertEqual(wire.decode_proof(wire.encode_proof(proof, context), context), proof)
        self.assertEqual(wire.decode_registration(wire.encode_registration(registration)),registration)
        with self.assertRaises((ValueError, DecodeError)):
            wire.decode_round_record(b'', 0, pp)

    def test_registration_rejects_malformed_generator_count_and_level(self):
        _, wire, _, registration, _, _ = self.fixture()
        tag, payload = read_frame(wire.encode_registration(registration))
        r = Reader(payload)
        r.blob(); r.blob(); r.uint()
        level_offset = r.offset
        r.uint()
        count_offset = r.offset
        count = r.uint()
        data = payload[r.offset:]
        for bad_count in (0, count-1, count+1, 2**63):
            malformed = payload[:count_offset]+encode_uint(bad_count)+data
            with self.assertRaises(DecodeError):
                wire.decode_registration(frame(tag,malformed))
        malformed = payload[:level_offset]+encode_uint(1)+payload[count_offset:]
        with self.assertRaises(DecodeError):
            wire.decode_registration(frame(tag,malformed))

    def test_every_top_level_decoder_rejects_trailing_bytes_and_cross_domains(self):
        _, wire, pp, registration, context, _ = self.fixture()
        pairs = [(wire.encode_pp(pp), wire.decode_pp),
                 (wire.encode_registration(registration), wire.decode_registration),
                 (wire.encode_context(context), wire.decode_context)]
        for raw, decode in pairs:
            for altered in (raw[:-1], raw+b'\0', frame(b'DF/unknown/v1',b'')):
                with self.assertRaises(DecodeError):
                    decode(altered)
            with self.assertRaises(DecodeError):
                decode(bytearray(raw))

    def test_resource_limits_apply_before_nested_objects(self):
        types,wire,pp,reg,ctx,proof=self.fixture()
        cases=[types.WireLimits(max_q_bytes=1), types.WireLimits(max_depth=1),
               types.WireLimits(max_module_rank=1),types.WireLimits(max_ring_degree=2),
               types.WireLimits(max_coefficients=8),types.WireLimits(max_metadata_bytes=2)]
        for limits in cases:
            with self.assertRaises(DecodeError):
                wire.decode_pp(wire.encode_pp(pp),limits=limits)
        with self.assertRaises(DecodeError):
            wire.decode_proof(wire.encode_proof(proof,ctx),ctx,
                              limits=types.WireLimits(max_total_bytes=10))
        with self.assertRaises(DecodeError):
            wire.decode_proof(wire.encode_proof(proof,ctx),ctx,
                              limits=types.WireLimits(max_integer_bytes=1))
        with self.assertRaises(DecodeError):
            wire.decode_registration(wire.encode_registration(reg),
                                     limits=types.WireLimits(max_file_length=8))
        payload=(encode_uint(257)+encode_uint(2)+encode_uint(2**1024)+encode_uint(4)
                 +encode_bytes(pp.codec)+encode_bytes(pp.suite))
        with self.assertRaises(DecodeError):
            wire.decode_pp(frame(b'DF/pp/v1',payload))
        with self.assertRaises((TypeError,ValueError)):
            types.WireLimits(max_depth=True)
        with self.assertRaises((TypeError,ValueError)):
            types.WireLimits(max_blob_bytes=-1)


if __name__ == '__main__':
    unittest.main()

