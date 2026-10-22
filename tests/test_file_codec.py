"""Exact byte/ternary codec tests; no cryptographic security assertions."""

import importlib.util
import io
import itertools
import random
import unittest

from damascus_a.codecs import FileCodec, checked_decode, checked_encode
from damascus_a.fold import FoldParameters


EXPECTED_DESCRIPTOR = (
    b'DF-Ternary32-v1;block-bytes=32;block-integer=unsigned-big-endian;'
    b'block-trits=min-c:3^c>=2^(8*r);trit-order=least-significant-first;'
    b'digit-map=0:0,1:1,2:-1;block-order=file;partial-block=actual-r-bytes;'
    b'high-trit-padding=0;flat-index=poly*n+degree;n=2^d;'
    b'global-padding=0-to-4^d;byte-length=registered-ell'
)


def oracle_trit_count(length):
    for count in itertools.count():
        if 3**count >= 256**length:
            return count


def oracle_encode(data, d):
    """Independent positional formula, not the implementation's divmod loop."""
    flat = []
    for offset in range(0, len(data), 32):
        block = data[offset:offset+32]
        value = sum(byte * 256**(len(block)-1-i) for i, byte in enumerate(block))
        for index in range(oracle_trit_count(len(block))):
            digit = value // 3**index % 3
            flat.append((0, 1, -1)[digit])
    n = 2**d
    if len(flat) > n*n:
        raise ValueError('oracle capacity exceeded')
    flat.extend([0] * (n*n-len(flat)))
    return tuple(tuple(flat[i*n:(i+1)*n]) for i in range(n))


def witness_with_flat(flat, d):
    n = 2**d
    return tuple(tuple(flat[i*n:(i+1)*n]) for i in range(n))


def encoded_integer(value, byte_length, d):
    flat = [(0, 1, -1)[value // 3**i % 3]
            for i in range(oracle_trit_count(byte_length))]
    flat.extend([0] * (4**d-len(flat)))
    return witness_with_flat(flat, d)


class ShortReader:
    def __init__(self, data, chunk_size=3):
        self.source = io.BytesIO(data)
        self.chunk_size = chunk_size
        self.requests = []

    def read(self, requested):
        self.requests.append(requested)
        return self.source.read(min(requested, self.chunk_size))


class FileCodecTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('damascus_a.file_codec'),
                             'the approved Ternary32 codec is not implemented')
        from damascus_a import file_codec
        self.module = file_codec
        self.codec = file_codec.Ternary32Codec()

    @staticmethod
    def parameters(d=5):
        return FoldParameters(d=d, T=4, k=1, q=2**521-1)

    def test_descriptor_fixes_mapping_and_implements_explicit_contract(self):
        self.assertIsInstance(self.codec, FileCodec)
        self.assertEqual(self.codec.descriptor, EXPECTED_DESCRIPTOR)
        self.assertEqual(self.module.TERNARY32_DESCRIPTOR, EXPECTED_DESCRIPTOR)
        with self.assertRaises(AttributeError):
            self.codec.descriptor = b'other'
        for length in range(33):
            self.assertEqual(self.module.trits_for_bytes(length), oracle_trit_count(length))
        self.assertEqual(self.module.trits_for_bytes(32), 162)
        for length in range(101):
            expected = 162*(length//32) + oracle_trit_count(length%32)
            self.assertEqual(self.module.required_coefficients(length), expected)

    def test_random_lengths_match_independent_base_three_oracle(self):
        parameters = self.parameters()
        for length in range(101):
            for seed in range(3):
                rng = random.Random(length*10+seed)
                data = rng.randbytes(length)
                with self.subTest(length=length, seed=seed):
                    witness = self.codec.encode(data, parameters)
                    self.assertEqual(witness, oracle_encode(data, parameters.d))
                    self.assertEqual(self.codec.decode(witness, length, parameters), data)
                    self.assertTrue(all(type(c) is int and c in (-1, 0, 1)
                                        for poly in witness for c in poly))

    def test_block_boundaries_leading_zeroes_and_extreme_bytes(self):
        p = self.parameters()
        for length in (0, 1, 2, 3, 31, 32, 33, 63, 64, 65, 95, 96, 97, 100):
            for data in (b'\x00'*length, b'\xff'*length, bytes(range(length)),
                         (b'\x00'*(length-1)+b'\x01') if length else b''):
                with self.subTest(length=length, data=data):
                    witness = self.codec.encode(data, p)
                    self.assertEqual(witness, oracle_encode(data, p.d))
                    self.assertEqual(self.codec.decode(witness, length, p), data)
        p = self.parameters(d=2)
        self.assertEqual(self.codec.encode(b'\x02', p)[0][:2], (-1, 0))
        self.assertEqual(self.codec.encode(b'\x03', p)[0][:2], (0, 1))
        self.assertEqual(self.codec.encode(b'\x01\x00', p), encoded_integer(256, 2, p.d))

    def test_capacity_exact_partial_and_full_32_byte_blocks(self):
        p = self.parameters(d=2)
        self.assertEqual(self.module.required_coefficients(3), 16)
        self.assertEqual(self.codec.decode(self.codec.encode(b'\xff'*3, p), 3, p), b'\xff'*3)
        with self.assertRaisesRegex(ValueError, 'capacity'):
            self.codec.encode(b'\x00'*4, p)
        p = self.parameters(d=4)
        for length in (31, 32, 33, 50):
            data = bytes(range(length))
            self.assertEqual(self.codec.decode(self.codec.encode(data, p), length, p), data)
        for length in (51, 63, 64):
            with self.assertRaisesRegex(ValueError, 'capacity'):
                self.codec.encode(b'\x00'*length, p)
        p = self.parameters(d=6)
        self.assertEqual(self.module.required_coefficients(809), 4**6)
        data = random.Random(50).randbytes(809)
        self.assertEqual(self.codec.decode(self.codec.encode(data, p), 809, p), data)
        with self.assertRaisesRegex(ValueError, 'capacity'):
            self.codec.encode(data+b'\x00', p)

    def test_decode_rejects_surplus_block_codewords_and_global_padding(self):
        for length, d in ((1, 2), (2, 2), (3, 2), (31, 4), (32, 4)):
            p = self.parameters(d)
            surplus = encoded_integer(256**length, length, d)
            with self.subTest(length=length), self.assertRaisesRegex(ValueError, 'codeword'):
                self.codec.decode(surplus, length, p)
        p = self.parameters(d=4)
        valid = self.codec.encode(b'\x00'*33, p)
        flat = [c for poly in valid for c in poly]
        # A surplus value in the final one-byte block must also reject.
        flat[162:168] = [c for poly in encoded_integer(256, 1, 2) for c in poly][:6]
        with self.assertRaisesRegex(ValueError, 'codeword'):
            self.codec.decode(witness_with_flat(flat, 4), 33, p)
        for length in (0, 1, 32, 33):
            flat = [c for poly in self.codec.encode(b'\x00'*length, p) for c in poly]
            flat[-1] = -1
            with self.subTest(length=length), self.assertRaisesRegex(ValueError, 'padding'):
                self.codec.decode(witness_with_flat(flat, 4), length, p)

    def test_decode_requires_exact_immutable_ternary_shape(self):
        p = self.parameters(d=2)
        witness = self.codec.encode(b'\x05', p)
        bad_witnesses = [list(witness), witness[:-1], witness+(witness[0],),
                         (witness[0][:-1],)+witness[1:],
                         (witness[0]+(0,),)+witness[1:],
                         (list(witness[0]),)+witness[1:]]
        bad_witnesses += [((bad,)+witness[0][1:],)+witness[1:]
                          for bad in (True, 1.0, '1', 2, -2)]
        for bad in bad_witnesses:
            with self.subTest(bad=bad), self.assertRaises((TypeError, ValueError)):
                self.codec.decode(bad, 1, p)
        for bad_length in (-1, True, 1.0, '1'):
            with self.assertRaises((TypeError, ValueError)):
                self.codec.decode(witness, bad_length, p)
        with self.assertRaisesRegex(ValueError, 'capacity'):
            self.codec.decode(witness, 4, p)
        for bad_data in (bytearray(b'x'), memoryview(b'x'), 'x', None):
            with self.assertRaises(TypeError):
                self.codec.encode(bad_data, p)
        for bad in (-1, True, 1.0, '1'):
            with self.assertRaises((TypeError, ValueError)):
                self.module.required_coefficients(bad)
        for bad in (-1, 33, True, 1.0):
            with self.assertRaises((TypeError, ValueError)):
                self.module.trits_for_bytes(bad)
        with self.assertRaises(TypeError):
            self.codec.encode(b'', None)
        with self.assertRaises((ValueError, OverflowError)):
            self.codec.encode(b'', self.parameters(d=10**100))

    def test_empty_and_registered_length_preserve_zero_bytes(self):
        for d in (0, 1, 2):
            p = self.parameters(d)
            witness = self.codec.encode(b'', p)
            self.assertEqual(witness, tuple((0,)*(2**d) for _ in range(2**d)))
            self.assertEqual(self.codec.decode(witness, 0, p), b'')
        p = self.parameters(d=2)
        zero = self.codec.encode(b'', p)
        self.assertEqual(self.codec.encode(b'\x00\x00', p), zero)
        self.assertEqual(self.codec.decode(zero, 2, p), b'\x00\x00')
        self.assertEqual(self.codec.decode(zero, 3, p), b'\x00\x00\x00')

    def test_checked_codec_contract_roundtrips_entire_vector(self):
        p = self.parameters()
        data = b'\x00'*32+b'\xff\x00'
        witness = checked_encode(self.codec, self.codec.descriptor, data, p)
        self.assertEqual(checked_decode(self.codec, self.codec.descriptor, witness, len(data), p), data)
        with self.assertRaises(ValueError):
            checked_encode(self.codec, b'wrong-descriptor', data, p)
        flat = [c for poly in witness for c in poly]
        flat[-1] = 1
        with self.assertRaises(ValueError):
            checked_decode(self.codec, self.codec.descriptor,
                           witness_with_flat(flat, p.d), len(data), p)

    def test_streaming_matches_materialized_encoding_and_handles_short_reads(self):
        p = self.parameters()
        for length in (0, 1, 31, 32, 33, 64, 65, 100):
            data = random.Random(length).randbytes(length)
            reader = ShortReader(data)
            actual = tuple(self.codec.iterencode(reader, length, p))
            expected = tuple(c for poly in oracle_encode(data, p.d) for c in poly)
            self.assertEqual(actual, expected)
            self.assertTrue(reader.requests)
            self.assertTrue(all(0 < request <= 32 for request in reader.requests))
            self.assertEqual(reader.source.tell(), length)

    def test_streaming_rejects_truncated_extra_or_nonbinary_readers(self):
        p = self.parameters(d=4)
        for data, declared in ((b'', 1), (b'a'*31, 32), (b'a'*32, 33),
                               (b'a', 0), (b'a'*33, 32), (b'a'*34, 33)):
            with self.subTest(actual=len(data), declared=declared), self.assertRaises(ValueError):
                tuple(self.codec.iterencode(io.BytesIO(data), declared, p))
        for reader in (object(), io.StringIO('abc')):
            with self.assertRaises(TypeError):
                tuple(self.codec.iterencode(reader, 3, p))
        class OversizedReader:
            def read(self, requested):
                return b'x'*(requested+1)
        with self.assertRaises(ValueError):
            tuple(self.codec.iterencode(OversizedReader(), 1, p))
        reader = ShortReader(b'')
        with self.assertRaisesRegex(ValueError, 'capacity'):
            self.codec.iterencode(reader, 51, p)
        self.assertEqual(reader.requests, [])

    def test_streaming_is_lazy_and_checks_extra_before_final_coefficients(self):
        reader = ShortReader(b'x'*1000000, chunk_size=32)
        stream = self.codec.iterencode(reader, 1000000, self.parameters(d=12))
        first = tuple(itertools.islice(stream, 162))
        self.assertEqual(first, tuple(c for poly in oracle_encode(b'x'*32, 4) for c in poly)[:162])
        self.assertEqual(reader.source.tell(), 32)
        self.assertEqual(reader.requests, [32])
        # Exact-capacity consumer still cannot receive all coefficients from an overlong file.
        stream = self.codec.iterencode(io.BytesIO(b'abcd'), 3, self.parameters(d=2))
        with self.assertRaises(ValueError):
            tuple(itertools.islice(stream, 16))


if __name__ == '__main__':
    unittest.main()
