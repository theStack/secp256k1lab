# The following functions are intentionally written in a C-like interface, as
# the primary purpose is help reviewing the "silentpayments" module PR in
# libsecp256k1 (PR #1765, see https://github.com/bitcoin-core/secp256k1/pull/1765)
# by providing an executable pseudo-code of it
from typing import List, NamedTuple, Optional

from .secp256k1 import GE, G, Scalar
from .util import tagged_hash


# internal functions (declared as "static" in the secp256k1 module)

def _create_input_hash(outpoint_smallest: bytes, pubkey_sum: GE) -> Scalar:
    assert len(outpoint_smallest) == 36
    data_to_hash = outpoint_smallest + pubkey_sum.to_bytes_compressed()
    return Scalar.from_bytes_checked(tagged_hash("BIP0352/Inputs", data_to_hash))


def _create_shared_secret(public_component: GE, secret_component: Scalar) -> bytes:
    shared_secret = (secret_component * public_component).to_bytes_compressed()
    assert len(shared_secret) == 33
    return shared_secret


def _create_output_tweak(shared_secret: bytes, k: int) -> Scalar:
    assert len(shared_secret) == 33
    assert (0 <= k < 2**32)
    data_to_hash = shared_secret + k.to_bytes(4, 'big')
    return Scalar.from_bytes_checked(tagged_hash("BIP0352/SharedSecret", data_to_hash))


def _create_output_pubkey(shared_secret: bytes, spend_pubkey: GE, k: int) -> bytes:
    assert len(shared_secret) == 33
    assert (0 <= k < 2**32)
    output_tweak = _create_output_tweak(shared_secret, k)
    return (spend_pubkey + output_tweak * G).to_bytes_xonly()


# public structs and functions (declared in the API header include/secp256k1_silentpayments.h)

#######################
##### Sender side #####
#######################

class silentpayments_recipient(NamedTuple):
    scan_pubkey: GE
    spend_pubkey: GE
    index_: int  # "index" is a built-in name in Python, so work-around that with postfix _


def silentpayments_sender_create_outputs(recipients: List[silentpayments_recipient], outpoint_smallest: bytes,
                                         taproot_seckeys: List[bytes], plain_seckeys: List[bytes]) -> List[bytes]:
    if (len(recipients) == 0):
        raise ValueError("At least one recipient must be provided.")
    if (len(outpoint_smallest) != 36):
        raise ValueError("The outpoint_smallest parameter must have a size of 36 bytes.")
    if (len(taproot_seckeys) + len(plain_seckeys)) == 0:
        raise ValueError("At least one secret key must be provided.")
    for i in range(len(recipients)):
        if recipients[i].index_ != i:
            raise ValueError("Recipient index mismatch.")

    # sum up secret keys: a_sum = a_1 + a_2 + ... + a_n
    seckey_sum = Scalar(0)
    for plain_seckey in plain_seckeys:
        seckey_sum += Scalar.from_bytes_checked(plain_seckey)
    # secret keys used for taproot outputs have to be negated if they result in an odd point
    for taproot_seckey in taproot_seckeys:
        addend = Scalar.from_bytes_checked(taproot_seckey)
        if not (Scalar.from_bytes_checked(taproot_seckey) * G).has_even_y():
            addend = -addend
        seckey_sum += addend
    # if sum results in zero, we have to abort (can't derive valid shared secret)
    if seckey_sum == 0:
        raise ValueError("Secret keys sum up to zero, invalid transaction.")

    # derive input_hash = hash(outpoint_smallest || A_sum)
    pubkey_sum = seckey_sum * G
    input_hash = _create_input_hash(outpoint_smallest, pubkey_sum)
    # calculate scalar_part of the shared secret
    shared_secret_scalar_part = input_hash * seckey_sum

    # group recipients by scan public key
    recipients.sort(key=lambda r: r.scan_pubkey.to_bytes_compressed())

    # create outputs
    created_outputs = [bytes()]*len(recipients)
    current_scan_pubkey = recipients[0].scan_pubkey
    k = 0
    for i in range(0, len(recipients)):
        if i == 0 or recipients[i].scan_pubkey != current_scan_pubkey:
            # if we are on a different scan pubkey, its time to recreate the shared secret and reset k to 0
            shared_secret = _create_shared_secret(recipients[i].scan_pubkey, shared_secret_scalar_part)
            k = 0
        output_xonly = _create_output_pubkey(shared_secret, recipients[i].spend_pubkey, k)
        created_outputs[recipients[i].index_] = output_xonly
        k += 1
        current_scan_pubkey = recipients[i].scan_pubkey

    assert all([len(co) == 32 for co in created_outputs])
    return created_outputs


##########################################
##### Receiver side - label creation #####
##########################################

def silentpayments_recipient_label_parse(label_ser: bytes) -> GE:
    return GE.from_bytes_compressed(label_ser)


def silentpayments_recipient_label_serialize(label: GE) -> bytes:
    return label.to_bytes_compressed()


def silentpayments_recipient_label_create(scan_key: bytes, m: int) -> tuple[GE, Scalar]:
    label_tweak = Scalar.from_bytes_checked(tagged_hash("BIP0352/Label", scan_key + m.to_bytes(4, 'big')))
    label = label_tweak * G
    return (label, label_tweak)


def silentpayments_recipient_create_labeled_spend_pubkey(unlabeled_spend_pubkey: GE, label: GE) -> GE:
    return unlabeled_spend_pubkey + label


####################################
##### Receiver side - scanning #####
####################################

# Note that in the secp256k1 PR this data type is opaque, i.e.
# from the API perspective these fields are not accessible
class silentpayments_prevouts_summary(NamedTuple):
    pubkey_sum: GE
    input_hash: Scalar


def silentpayments_recipient_prevouts_summary_create(outpoint_smallest: bytes, xonly_pubkeys: List[GE],
                                                     plain_pubkeys: List[GE]) -> silentpayments_prevouts_summary:
    # sum up public keys: A_sum = A_1 + A_2 + ... + A_n
    pubkey_sum = GE()
    for xonly_pubkey in xonly_pubkeys:
        assert xonly_pubkey.has_even_y()  # per definition of x-only pubkeys
        pubkey_sum += xonly_pubkey
    for plain_pubkey in plain_pubkeys:
        pubkey_sum += plain_pubkey
    # if sum results in point at infinity, we have to abort (can't derive valid shared secret)
    if pubkey_sum.infinity:
        raise ValueError("Public keys sum up to point at infinity, invalid transaction.")

    # derive input_hash = hash(outpoint_smallest || A_sum)
    input_hash = _create_input_hash(outpoint_smallest, pubkey_sum)

    return silentpayments_prevouts_summary(pubkey_sum, input_hash)


class silentpayments_found_output(NamedTuple):
    output: bytes  # serialized x-only pubkey
    tweak: Scalar  # tweak needed to spend the output (with seckey = spend_seckey + tweak)
    found_with_label: bool
    label: GE


# to keep it simple, the label lookup is implemented here by passing the labels cache directly
def silentpayments_recipient_scan_outputs(tx_outputs: List[Optional[bytes]], scan_key: bytes,
                                          prevouts_summary: silentpayments_prevouts_summary,
                                          unlabeled_spend_pubkey: GE,
                                          labels_cache: Optional[dict[bytes, bytes]]) -> List[silentpayments_found_output]:
    # calculate the shared secret
    shared_secret_scalar_part = prevouts_summary.input_hash * Scalar.from_bytes_checked(scan_key)
    shared_secret = _create_shared_secret(prevouts_summary.pubkey_sum, shared_secret_scalar_part)

    # scan through all outputs starting with k = 0;
    # if an output is found, repeat with k = 1, etc.
    found_outputs = []
    found_idx = 0
    for k in range(0, len(tx_outputs)):
        output_tweak = _create_output_tweak(shared_secret, k)
        output_ge = unlabeled_spend_pubkey + (output_tweak * G)
        output_xonly = output_ge.to_bytes_xonly()
        found = False
        label_tweak = None
        for j in range(0, len(tx_outputs)):
            if tx_outputs[j] is None:  # skip already-matched outputs
                continue
            # check for direct match (no labels involved)
            if output_xonly == tx_outputs[j]:
                found = True
                found_idx = j
                break

            # scan for labels, if a labels cache is available (passed as lookup function in secp PR)
            if labels_cache is not None:
                tx_output_ge = GE.from_bytes_xonly(tx_outputs[j])
                # calculate first scan label candidate
                label_ge = tx_output_ge - output_ge
                label33 = label_ge.to_bytes_compressed()
                label_tweak = labels_cache.get(label33)
                if label_tweak is not None:
                    found = True
                    found_idx = j
                    break

                # calculate second scan label candidate
                label_ge = -tx_output_ge - output_ge
                label33 = label_ge.to_bytes_compressed()
                label_tweak = labels_cache.get(label33)
                if label_tweak is not None:
                    found = True
                    found_idx = j
                    break

        if found:
            fo_output = tx_outputs[found_idx]
            assert fo_output is not None
            tx_outputs[found_idx] = None  # mark this output as matched
            fo_tweak = output_tweak
            if label_tweak is not None:
                fo_found_with_label = True
                fo_tweak += Scalar.from_bytes_checked(label_tweak)
                fo_label = label_ge
            else:
                fo_found_with_label = False
                fo_label = GE()  # invalid label
            found_outputs.append(silentpayments_found_output(fo_output, fo_tweak, fo_found_with_label, fo_label))

            # reset everything for the next round of scanning
            label_tweak = None
        else:
            break

    return found_outputs


### Alternative "LabelSet scanning" approach #######################################################
#
# The following is an alternative scanning approach which ought to be faster if the
# number of labels to scan for is reasonably small. Rather than iterating through all tx outputs
# and calculating possible label candidates to look up in the labels cache (that's the
# "BIP scanning" approach and the one currently implemented in secp PR #1765), it works by
# doing it in the other direction: for each label in the passed label set, calculate the
# possible tx output candidate and look it up in the list of tx outputs to detect if there
# is a match. For a fast lookup in the tx outputs, these are sorted first and then found
# via binary search. Note that in contrast to the "BIP scanning" approach, the tx outputs
# are not treated as group elements, as we don't do any elliptic curve calculations with
# them, so passing them in their raw x-only serialization is sufficient.
# 
# see https://gist.github.com/theStack/25c77747838610931e8bbeb9d76faf78
# for a description with benchmark results, comparing the BIP and LabelSet approaches
####################################################################################################

def _silentpayments_tx_output_find(tx_outputs_sorted: List[bytes], tx_output: bytes) -> int:
    import bisect  # in the secp256k1 module, this is implemented using handwritten binary search
    idx = bisect.bisect_left(tx_outputs_sorted, tx_output)
    if idx != len(tx_outputs_sorted) and tx_outputs_sorted[idx] == tx_output:
        return idx
    else:
        return -1


def silentpayments_recipient_scan_outputs_with_labelset(tx_outputs: List[bytes], scan_key: bytes,
                                                        prevouts_summary: silentpayments_prevouts_summary,
                                                        unlabeled_spend_pubkey: GE,
                                                        label_set_to_scan: List[tuple[GE, bytes]]) -> List[silentpayments_found_output]:
    # calculate the shared secret
    shared_secret_scalar_part = prevouts_summary.input_hash * Scalar.from_bytes_checked(scan_key)
    shared_secret = _create_shared_secret(prevouts_summary.pubkey_sum, shared_secret_scalar_part)

    # sort transaction outputs to find them fast using binary search
    tx_outputs.sort()

    # scan through all outputs starting with k = 0;
    # if an output is found, repeat with k = 1, etc.
    found_outputs = []
    for k in range(0, len(tx_outputs)):
        unlabeled_output_tweak = _create_output_tweak(shared_secret, k)
        unlabeled_output_ge = unlabeled_spend_pubkey + (unlabeled_output_tweak * G)
        unlabeled_output_xonly = unlabeled_output_ge.to_bytes_xonly()
        # check for direct match (no labels involved)
        idx = _silentpayments_tx_output_find(tx_outputs, unlabeled_output_xonly)
        if idx >= 0:
            found_outputs.append(silentpayments_found_output(
                unlabeled_output_xonly, unlabeled_output_tweak, False, GE()
            ))
            continue  # we had a match, continue with next k value

        # check for label matches by iterating through all of them and
        # look up each output candidate in the list of tx outputs
        labeled_match = False
        for (label_ge, label_tweak) in label_set_to_scan:
            labeled_output_ge = unlabeled_output_ge + label_ge
            labeled_output_xonly = labeled_output_ge.to_bytes_xonly()
            idx = _silentpayments_tx_output_find(tx_outputs, labeled_output_xonly)
            if idx >= 0:
                labeled_output_tweak = unlabeled_output_tweak + label_tweak
                found_outputs.append(silentpayments_found_output(
                    labeled_output_xonly, labeled_output_tweak, True, label_ge
                ))
                labeled_match = True
                break  # leave label set iteration loop
        if labeled_match:
            continue  # we had a match, continue with next k value

        # no match, stop searching further
        break

    return found_outputs
