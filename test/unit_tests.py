#!/usr/bin/env python3
from pathlib import Path
from random import randbytes
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent / "../src/"))
from secp256k1lab.bip340 import pubkey_gen, schnorr_sign, schnorr_verify
from secp256k1lab.ecdh import ecdh_libsecp256k1
from secp256k1lab.keys import pubkey_gen_plain


class UnitTests(unittest.TestCase):
    def test_bip340(self):
        """Test schnorr signatures (BIP 340)."""
        # TODO: test against testvectors (see https://github.com/secp256k1lab/secp256k1lab/issues/1)
        seckey = randbytes(32)
        pubkey_xonly = pubkey_gen(seckey)
        aux_rand = randbytes(32)
        message = b'this is some arbitrary message'
        signature = schnorr_sign(message, seckey, aux_rand)
        success = schnorr_verify(message, pubkey_xonly, signature)
        self.assertTrue(success)

    def test_ecdh(self):
        """Test ECDH."""
        seckey_alice = randbytes(32)
        pubkey_alice = pubkey_gen_plain(seckey_alice)
        seckey_bob = randbytes(32)
        pubkey_bob = pubkey_gen_plain(seckey_bob)
        shared_secret1 = ecdh_libsecp256k1(seckey_alice, pubkey_bob)
        shared_secret2 = ecdh_libsecp256k1(seckey_bob, pubkey_alice)
        self.assertEqual(shared_secret1, shared_secret2)


if __name__ == "__main__":
    unittest.main()
