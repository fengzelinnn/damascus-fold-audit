import hashlib
import unittest

from damascus_a.algebra import Ring
from damascus_a.fold import (FoldParameters, initialize, vector_cross_terms,
    vector_prove, polynomial_cross_terms, polynomial_prove, RoundRecord, final_open)
from damascus_a.protocol_types import ProtocolParameters, Registration, EpochContext, EpochProof
from damascus_a.transcript import context_digest, vector_challenge, polynomial_challenge
from damascus_a.wire import encode_proof, encode_registration, encode_context
from damascus_a.protocol_artifacts import serialization_evidence


class ProtocolArtifactTests(unittest.TestCase):
    def example(self):
        p=FoldParameters(1,4,2,(1<<31)-1);ring=Ring(p.q,2)
        g=tuple(tuple(ring.element((i+j+1,i+2*j+3)) for j in range(2)) for i in range(2))
        state=initialize(p,((1,-1),(0,1)),g)
        pp=ProtocolParameters(p,b'TEST-ONLY-explicit-witness')
        reg=Registration(pp,b'test-file',1,state.public)
        ctx=EpochContext(reg,b'epoch',b'seed',b'external-deadline')
        lv,rv=vector_cross_terms(state)
        x=vector_challenge(ctx,(),0,lv,rv);middle=vector_prove(state,x,lv,rv)
        lp,rp=polynomial_cross_terms(middle);record=RoundRecord(lv,rv,lp,rp)
        y=polynomial_challenge(ctx,(),0,record)
        end=polynomial_prove(middle,y,lp,rp)
        proof=EpochProof(context_digest(ctx),(record,),final_open(end))
        return ctx,encode_proof(proof,ctx)

    def test_actual_proof_partition_and_external_materials_are_distinct(self):
        ctx,raw=self.example()
        result=serialization_evidence(ctx,raw,epoch_evidence=b'certificate',publication_evidence=b'receipt')
        serial=result['serialization'];parts=serial['parts']
        self.assertEqual(bytes.fromhex(serial['full_proof']['hex']),raw)
        self.assertEqual(serial['registration']['bytes'],len(encode_registration(ctx.registration)))
        self.assertEqual(b''.join(bytes.fromhex(p['artifact']['hex']) for p in parts),raw)
        self.assertEqual(sum(p['artifact']['bytes'] for p in parts),len(raw))
        self.assertEqual([p['kind'] for p in parts].count('round_record'),1)
        self.assertEqual(parts[-1]['kind'],'terminal_opening')
        for part in parts:
            artifact=part['artifact'];data=bytes.fromhex(artifact['hex'])
            self.assertEqual(artifact['sha256'],hashlib.sha256(data).hexdigest())
            self.assertEqual(raw[part['offset']:part['offset']+len(data)],data)
        aux=result['auxiliary_artifacts']
        self.assertEqual(aux['context']['bytes'],len(encode_context(ctx)))
        self.assertEqual(aux['epoch_evidence']['bytes'],11)
        self.assertEqual(aux['publication_evidence']['bytes'],7)
        self.assertFalse(result['network_transfer_measured'])
        self.assertFalse(result['proof_acceptance_established'])

    def test_malformed_or_wrong_context_proof_rejects(self):
        ctx,raw=self.example()
        for bad in (raw[:-1],raw+b'junk',b'not-a-proof'):
            with self.subTest(bad=bad[:8]),self.assertRaises(ValueError):
                serialization_evidence(ctx,bad)
        other=EpochContext(ctx.registration,b'other',ctx.seed,ctx.deadline)
        with self.assertRaises(ValueError):serialization_evidence(other,raw)

    def test_missing_evidence_is_absent_not_zero_byte_certification(self):
        ctx,raw=self.example();result=serialization_evidence(ctx,raw)
        self.assertIsNone(result['auxiliary_artifacts']['epoch_evidence'])
        self.assertIsNone(result['auxiliary_artifacts']['publication_evidence'])
        with self.assertRaises(TypeError):serialization_evidence(ctx,raw,epoch_evidence=True)


if __name__=='__main__':unittest.main()
