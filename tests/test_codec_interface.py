"""A deliberately tiny TEST ONLY codec exercises the abstract boundary.

It supports b'', b'A', b'B', b'AB' only and is not a proposed file encoding.
"""
import unittest

from damascus_a.codecs import FileCodec, checked_decode, checked_encode
from damascus_a.fold import FoldParameters


class TinyTestCodec(FileCodec):
    descriptor = b'TEST_ONLY-tiny-alphabet-v1'
    _words = {b'': (), b'A': (1,), b'B': (-1,), b'AB': (1, -1)}

    def encode(self, data, parameters):
        digits = self._words[data]
        n = 1 << parameters.d
        if len(digits) > n * n:
            raise ValueError('test codec capacity')
        flat = digits + (0,) * (n * n - len(digits))
        return tuple(flat[i:i+n] for i in range(0, len(flat), n))

    def decode(self, witness, file_length, parameters):
        flat = sum(witness, ())
        for word, digits in self._words.items():
            if len(word) == file_length and flat[:len(digits)] == digits:
                return word
        raise ValueError('outside test codec image')


class CodecTests(unittest.TestCase):
    def setUp(self):
        self.p = FoldParameters(d=1, T=4, k=2, q=2147483647)
        self.codec = TinyTestCodec()

    def test_explicit_codec_roundtrip_and_padding(self):
        for data in TinyTestCodec._words:
            witness = checked_encode(self.codec, self.codec.descriptor, data, self.p)
            self.assertEqual(checked_decode(self.codec, self.codec.descriptor,
                                            witness, len(data), self.p), data)

    def test_descriptor_is_required_and_matched(self):
        for codec, descriptor in ((None, self.codec.descriptor), (self.codec, b'wrong'),
                                  (self.codec, ''), (object(), self.codec.descriptor)):
            with self.subTest(codec=codec), self.assertRaises((TypeError, ValueError)):
                checked_encode(codec, descriptor, b'A', self.p)

    def test_noncanonical_padding_rejected_despite_decodable_prefix(self):
        with self.assertRaisesRegex(ValueError, 'canonical'):
            checked_decode(self.codec, self.codec.descriptor, ((1, 0), (0, 1)), 1, self.p)

    def test_shapes_integer_bounds_and_length_are_checked(self):
        for witness in (((1, 0),), ((1,), (0,)), ((2, 0), (0, 0)),
                        ((True, 0), (0, 0)), [[1, 0], [0, 0]]):
            with self.subTest(witness=witness), self.assertRaises((TypeError, ValueError)):
                checked_decode(self.codec, self.codec.descriptor, witness, 1, self.p)
        for length in (True, -1, 1.0):
            with self.assertRaises((TypeError, ValueError)):
                checked_decode(self.codec, self.codec.descriptor, ((1, 0), (0, 0)), length, self.p)

    def test_decoder_length_and_encoder_roundtrip_must_be_exact(self):
        class WrongLength(TinyTestCodec):
            def decode(self, witness, file_length, parameters):
                return b'AB'
        class WrongEncoder(TinyTestCodec):
            def encode(self, data, parameters):
                return super().encode(b'B', parameters)
        with self.assertRaises(ValueError):
            checked_decode(WrongLength(), self.codec.descriptor, ((1, 0), (0, 0)), 1, self.p)
        with self.assertRaises(ValueError):
            checked_encode(WrongEncoder(), self.codec.descriptor, b'A', self.p)

    def test_no_default_codec_and_huge_depth_rejected_by_supplied_shape(self):
        with self.assertRaises(TypeError):
            FileCodec()
        p = FoldParameters(d=10**100, T=4, k=1, q=17)
        with self.assertRaises(ValueError):
            checked_decode(self.codec, self.codec.descriptor, ((1,),), 1, p)


if __name__ == '__main__':
    unittest.main()
