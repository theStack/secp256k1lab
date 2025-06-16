import unittest

from secp256k1lab.secp256k1 import FE, Scalar


class LowLevelPrimeFieldTests(unittest.TestCase):
    """Test low-level secp256k1 field arithmetic classes."""

    def test_constructors(self):
        P = FE.SIZE
        N = Scalar.SIZE

        # wrapping constructors
        for init_value, reduced_value in [(0, 0), (P-1, P-1), (P, 0), (P+1, 1)]:
            fe1 = FE(init_value)
            fe2 = FE.from_int_wrapping(init_value)
            fe3 = FE.from_bytes_wrapping(init_value.to_bytes(32, 'big'))
            self.assertEqual(int(fe1), reduced_value)
            self.assertEqual(int(fe1), int(fe2))
            self.assertEqual(int(fe2), int(fe3))

        for init_value, reduced_value in [(0, 0), (N-1, N-1), (N, 0), (N+1, 1)]:
            s1 = Scalar(init_value)
            s2 = Scalar.from_int_wrapping(init_value)
            s3 = Scalar.from_bytes_wrapping(init_value.to_bytes(32, 'big'))
            self.assertEqual(int(s1), reduced_value)
            self.assertEqual(int(s1), int(s2))
            self.assertEqual(int(s2), int(s3))

        # checking constructors (should throw on overflow)
        for valid_value in [0, P-1]:
            fe1 = FE.from_int_checked(valid_value)
            fe2 = FE.from_bytes_checked(valid_value.to_bytes(32, 'big'))
            self.assertEqual(int(fe1), valid_value)
            self.assertEqual(int(fe1), int(fe2))

        for overflow_value in [P, P+1]:
            with self.assertRaises(ValueError):
                _ = FE.from_int_checked(overflow_value)
            with self.assertRaises(ValueError):
                _ = FE.from_bytes_checked(overflow_value.to_bytes(32, 'big'))

        for valid_value in [0, N-1]:
            s1 = Scalar.from_int_checked(valid_value)
            s2 = Scalar.from_bytes_checked(valid_value.to_bytes(32, 'big'))
            self.assertEqual(int(s1), valid_value)
            self.assertEqual(int(s1), int(s2))

        for overflow_value in [N, N+1]:
            with self.assertRaises(ValueError):
                _ = Scalar.from_int_checked(overflow_value)
            with self.assertRaises(ValueError):
                _ = Scalar.from_bytes_checked(overflow_value.to_bytes(32, 'big'))

        # non-zero checking constructors (should throw on zero or overflow, only for Scalar)
        for valid_value in [1, N-1]:
            s1 = Scalar.from_int_nonzero_checked(valid_value)
            s2 = Scalar.from_bytes_nonzero_checked(valid_value.to_bytes(32, 'big'))
            self.assertEqual(int(s1), valid_value)
            self.assertEqual(int(s1), int(s2))

        for invalid_value in [0, N]:
            with self.assertRaises(ValueError):
                _ = Scalar.from_int_nonzero_checked(invalid_value)
            with self.assertRaises(ValueError):
                _ = Scalar.from_bytes_nonzero_checked(invalid_value.to_bytes(32, 'big'))
