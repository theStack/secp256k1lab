import hashlib
import json
from pathlib import Path
from typing import List, NamedTuple
import unittest

from secp256k1lab.bip340 import schnorr_sign
from secp256k1lab.bip352 import (
    silentpayments_sender_create_outputs,
    silentpayments_recipient,
    silentpayments_recipient_label_create,
    silentpayments_recipient_label_parse,
    silentpayments_recipient_label_serialize,
    #silentpayments_recipient_create_labeled_spend_pubkey,
    silentpayments_recipient_prevouts_summary_create,
    silentpayments_recipient_scan_outputs,
    silentpayments_recipient_scan_outputs_with_labelset,
)
from secp256k1lab.secp256k1 import GE, G, Scalar


# test data extraction functionality copied from secp256k1 PR #1765, tools/tests_silentpayments_generate.py
NUMS_H = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")

def sha256(s):
    return hashlib.sha256(s).digest()

def smallest_outpoint(outpoints):
    serialized_outpoints = [bytes.fromhex(txid)[::-1] + n.to_bytes(4, 'little') for txid, n in outpoints]
    return sorted(serialized_outpoints)[0]

def is_p2tr(s):  # OP_1 OP_PUSHBYTES_32 <32 bytes>
    return (len(s) == 34) and (s[0] == 0x51) and (s[1] == 0x20)

def get_pubkey_from_input(input_data, pubkey_hex):
    """Extract the correct pubkey for an input, handling NUMS_H filtering and format conversion"""
    spk = bytes.fromhex(input_data['prevout']['scriptPubKey']['hex'])
    pubkey = bytes.fromhex(pubkey_hex)

    if is_p2tr(spk):  # taproot input
        # Check for NUMS_H in witness (should be skipped)
        witness = bytes.fromhex(input_data.get('txinwitness', ''))
        # Parse witness stack
        witness_stack = []
        num_witness_items = 0
        if len(witness) > 0:
            num_witness_items = witness[0]
            witness = witness[1:]
        for i in range(num_witness_items):
            item_len = witness[0]
            witness_stack.append(witness[1:item_len+1])
            witness = witness[item_len+1:]

        # Check for script-path spend with NUMS_H
        if len(witness_stack) > 1 and witness_stack[-1][0] == 0x50:
            witness_stack.pop()
        if len(witness_stack) > 1:  # script-path spend?
            control_block = witness_stack[-1]
            internal_key = control_block[1:33]
            if internal_key == NUMS_H:  # skip
                return b''

        # Convert to x-only (32 bytes) for taproot
        if len(pubkey) == 33:
            pubkey = pubkey[1:]  # Remove prefix byte
        return pubkey
    else:  # regular input - use full compressed pubkey (33 bytes)
        return pubkey


class InputKeyMaterial(NamedTuple):
    plain_seckeys: List[bytes]
    taproot_seckeys: List[bytes]
    plain_pubkeys: List[GE]
    xonly_pubkeys: List[GE]
    smallest_outpoint: bytes


class BIP352Tests(unittest.TestCase):
    """Test Silent Payments (BIP 352)."""
    def test_vectors(self):
        # Test against vectors from the BIPs repository
        # [https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json]
        vectors_file = Path(__file__).parent / "vectors" / "bip352-send_and_receive.json"
        with open(vectors_file) as jsonfile:
            test_vectors = json.load(jsonfile)
            for test_i, test_vector in enumerate(test_vectors):
                with self.subTest(i=test_i):
                    print(f"\n===== BIP352 test case {test_i} -> {test_vector['comment']} =====")  # TODO: remove
                    input_key_material = self.get_input_key_material(test_vector)
                    self.subtest_vectors_case_sending(test_vector['sending'], input_key_material)
                    self.subtest_vectors_case_receiving(test_vector['receiving'], input_key_material)

    def get_input_key_material(self, test_vector):
        # determine input private and public keys, grouped into plain and taproot/x-only
        input_plain_seckeys = []
        input_taproot_seckeys = []
        input_plain_pubkeys = []
        input_xonly_pubkeys = []
        outpoints = []

        pubkey_index = 0
        input_pubkeys_hex = test_vector['sending'][0]['expected']['input_pub_keys']

        for vec in test_vector['sending'][0]['given']['vin']:
            outpoints.append((vec['txid'], vec['vout']))

            if pubkey_index < len(input_pubkeys_hex):
                seckey = bytes.fromhex(vec['private_key'])
                assert len(seckey) == 32
                pubkey = get_pubkey_from_input(vec, input_pubkeys_hex[pubkey_index])
                if len(pubkey) == 33:  # regular input
                    input_plain_seckeys.append(seckey)
                    input_plain_pubkeys.append(GE.from_bytes_compressed(pubkey))
                    pubkey_index += 1
                elif len(pubkey) == 32:  # taproot input
                    input_taproot_seckeys.append(seckey)
                    input_xonly_pubkeys.append(GE.from_bytes_xonly(pubkey))
                    pubkey_index += 1
                # len(pubkey) == 0, it's a NUMS_H input - skip without incrementing

        outpoint_L = smallest_outpoint(outpoints)
        return InputKeyMaterial(input_plain_seckeys, input_taproot_seckeys,
            input_plain_pubkeys, input_xonly_pubkeys, outpoint_L)

    def subtest_vectors_case_sending(self, test_vector, ikm):
        assert len(test_vector) == 1
        test_vector = test_vector[0]

        recipients = []
        for index, recipient_data in enumerate(test_vector['given']['recipients']):
            recipients.append(silentpayments_recipient(
                GE.from_bytes_compressed(bytes.fromhex(recipient_data['scan_pub_key'])),
                GE.from_bytes_compressed(bytes.fromhex(recipient_data['spend_pub_key'])),
                index
            ))

        expected_outputs_candidates = []
        for outputs in test_vector['expected']['outputs']:
            expected_outputs_candidate = []
            for output in outputs:
                expected_outputs_candidate.append(bytes.fromhex(output))
            expected_outputs_candidates.append(expected_outputs_candidate)

        try:
            created_outputs = silentpayments_sender_create_outputs(recipients, ikm.smallest_outpoint,
                ikm.taproot_seckeys, ikm.plain_seckeys)
        except Exception:
            # if exception occured, treat this as "no outputs created"
            created_outputs = []

        success = False
        for expected_outputs_candidate in expected_outputs_candidates:
            if sorted(created_outputs) == sorted(expected_outputs_candidate):
                success = True
                break
        if not success:
            print(f"created outputs: {[c.hex() for c in created_outputs]}")
            print( "expected outputs: ")
            for expected_outputs_candidate in expected_outputs_candidates:
                print(f"    {[e.hex() for e in expected_outputs_candidate]}")
        self.assertTrue(success)

    def subtest_vectors_case_receiving(self, test_vector, ikm):
        if len(test_vector) != 1:
            print("TODO: skipping receiving test for now, need to support multiple sub-cases")
        test_vector = test_vector[0]

        outputs_to_check = [bytes.fromhex(o) for o in test_vector['given']['outputs']]
        scan_seckey = bytes.fromhex(test_vector['given']['key_material']['scan_priv_key'])
        spend_seckey = bytes.fromhex(test_vector['given']['key_material']['spend_priv_key'])
        spend_pubkey = Scalar.from_bytes_checked(spend_seckey) * G

        try:
            prevouts_summary = silentpayments_recipient_prevouts_summary_create(
                ikm.smallest_outpoint, ikm.xonly_pubkeys, ikm.plain_pubkeys)
            all_input_pubkeys = ikm.plain_pubkeys + ikm.xonly_pubkeys
            self.assertEqual(GE.sum(*all_input_pubkeys), prevouts_summary.pubkey_sum)
        except Exception:
            assert test_vector['expected']['outputs'] == []
            return

        labels_cache = None
        label_integers = test_vector['given']['labels']
        if label_integers:
            labels_cache = {}
            for m in label_integers:
                label, label_tweak = silentpayments_recipient_label_create(scan_seckey, m)
                labels_cache[silentpayments_recipient_label_serialize(label)] = label_tweak.to_bytes()

        found_outputs = silentpayments_recipient_scan_outputs(outputs_to_check, scan_seckey, prevouts_summary,
            spend_pubkey, labels_cache)

        # test for alternative "LabelSet scanning" approach
        label_set = []
        if labels_cache is not None:
            for label, label_tweak in labels_cache.items():
                label_set.append((silentpayments_recipient_label_parse(label), Scalar.from_bytes_checked(label_tweak)))
        outputs_to_check = [bytes.fromhex(o) for o in test_vector['given']['outputs']]  # restore outputs
        found_outputs2 = silentpayments_recipient_scan_outputs_with_labelset(
            outputs_to_check, scan_seckey, prevouts_summary, spend_pubkey, label_set)
        self.assertEqual(found_outputs, found_outputs2)

        # also check tweaks
        MSG = sha256(b"message")
        AUX = sha256(b"random auxiliary data")
        found_signatures = []
        for found_output in found_outputs:
            full_seckey = (Scalar.from_bytes_checked(spend_seckey) + found_output.tweak).to_bytes()
            signature = schnorr_sign(MSG, full_seckey, AUX)
            found_signatures.append(signature)

        # compare expected and scanned outputs (including calculated seckey tweaks and signatures)
        matches = 0
        for i, found_output in enumerate(found_outputs):
            for expected_output_data in test_vector['expected']['outputs']:
                expected_output = bytes.fromhex(expected_output_data['pub_key'])
                if found_output.output == expected_output:
                    assert found_output.tweak.to_bytes() == bytes.fromhex(expected_output_data['priv_key_tweak'])
                    assert found_signatures[i] == bytes.fromhex(expected_output_data['signature'])
                    matches += 1
                    break

        success = matches == len(found_outputs) == len(test_vector['expected']['outputs'])
        if not success:
            print(f"found outputs: {[o.output.hex() for o in found_outputs]}")
            print(f"expected outputs: {[o for o in test_vector['expected']['outputs']]}")
        self.assertTrue(success)
