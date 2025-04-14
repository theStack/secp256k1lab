from random import randbytes
import unittest

from secp256k1lab.bip340 import pubkey_gen, schnorr_sign, schnorr_verify


class BIP340Tests(unittest.TestCase):
    """Test schnorr signatures (BIP 340)."""
    # TODO: test against testvectors (see https://github.com/secp256k1lab/secp256k1lab/issues/1)

    def test_correctness(self):
        seckey = randbytes(32)
        pubkey_xonly = pubkey_gen(seckey)
        aux_rand = randbytes(32)
        message = b'this is some arbitrary message'
        signature = schnorr_sign(message, seckey, aux_rand)
        success = schnorr_verify(message, pubkey_xonly, signature)
        self.assertTrue(success)
