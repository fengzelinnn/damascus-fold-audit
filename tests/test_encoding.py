import unittest

from damascus_a.encoding import DecodeError, Reader, encode_uint, encode_sint, encode_bytes, encode_field, decode_field, frame, read_frame


class EncodingTests(unittest.TestCase):
    def test_unsigned_roundtrip_and_exact_vectors(self):
        self.assertEqual(encode_uint(0), b'\0\0\0\0')
        self.assertEqual(encode_uint(256), b'\0\0\0\2\1\0')
        for value in (0, 1, 255, 256, 2**521-1):
            r = Reader(encode_uint(value)); self.assertEqual(r.uint(), value); r.finish()

    def test_signed_roundtrip_preserves_integer_lift(self):
        for value in (0, -1, 1, -(2**521), 2**521):
            r=Reader(encode_sint(value)); self.assertEqual(r.sint(), value); r.finish()
        self.assertNotEqual(encode_sint(-1), encode_sint(1))

    def test_rejects_noncanonical_and_truncated(self):
        for raw in (b'\0\0\0\1\0', b'\0\0\0\2\0\1', b'\0\0\0\2\1'):
            with self.assertRaises(DecodeError): Reader(raw).uint()
        for raw in (b'\1\0\0\0\0', b'\2\0\0\0\0'):
            with self.assertRaises(DecodeError): Reader(raw).sint()
        with self.assertRaises(DecodeError): Reader(b'\xff'*4).blob()
        with self.assertRaises(DecodeError): Reader(b'abc', max_total=2)
        with self.assertRaises(DecodeError): Reader(b'a').finish()

    def test_types_and_resource_bounds(self):
        for value in (True, -1, 1.0, '1'):
            with self.assertRaises((ValueError,TypeError)): encode_uint(value)
        with self.assertRaises(ValueError): encode_uint(256, max_bytes=1)
        with self.assertRaises(ValueError): encode_bytes(b'ab', max_bytes=1)

    def test_field_rejects_modular_aliases(self):
        self.assertEqual(encode_field(256,257), b'\1\0')
        self.assertEqual(decode_field(b'\1\0',257),256)
        for raw in (b'\1\1',b'\0',b'\0\0\0'):
            with self.assertRaises(DecodeError): decode_field(raw,257)
        with self.assertRaises(ValueError): encode_field(-1,257)
        with self.assertRaises(ValueError): encode_field(257,257)

    def test_frames_bind_types_and_boundaries(self):
        self.assertNotEqual(frame(b'a', b'bc'), frame(b'ab', b'c'))
        self.assertNotEqual(frame(b'vec', b'abc'), frame(b'poly', b'abc'))
        self.assertEqual(read_frame(frame(b'vec',b'abc')), (b'vec',b'abc'))
        with self.assertRaises(DecodeError): read_frame(frame(b'vec',b'abc')+b'x')

