# The following functions are intentionally written in a C-like interface, as
# the primary purpose is help reviewing the "silentpayments" module PR in
# libsecp256k1 (PR #1765, see https://github.com/bitcoin-core/secp256k1/pull/1765)
# by providing an executable pseudo-code of it
from typing import List, NamedTuple

from .secp256k1 import FE, GE, G, Scalar
from .util import tagged_hash


class silentpayments_recipient(NamedTuple):
    scan_pubkey: GE
    spend_pubkey: GE
    index: int


class silentpayments_prevouts_summary:
    # Note that in the secp256k1 PR this data type is opaque, i.e.
    # from the API perspective these fields are not accessible
    pubkey_sum: GE
    input_hash: Scalar


def _create_input_hash(outpoint_smallest: bytes, pubkey_sum: GE) -> Scalar:
    assert len(outpoint_smallest) == 36
    data_to_hash = outpoint_smallest + pubkey_sum.to_bytes_compressed()
    return Scalar.from_bytes_checked(tagged_hash("BIP0352/Inputs", data_to_hash))


def _create_output_tweak(shared_secret: bytes, k: int) -> Scalar:
    assert len(shared_secret) == 33
    data_to_hash = shared_secret + k.to_bytes(4, 'big')
    return Scalar.from_bytes_checked(tagged_hash("BIP0352/SharedSecret", data_to_hash))


def silentpayments_sender_create_outputs(recipients: List[silentpayments_recipient], outpoint_smallest: bytes,
                                         taproot_seckeys: List[bytes], plain_seckeys: List[bytes]) -> List[bytes]:
    if (len(recipients) == 0):
        raise ValueError("At least one recipient must be provided.")
    if (len(outpoint_smallest) != 36):
        raise ValueError("The outpoint_smallest parameter must have a size of 36 bytes.")
    if (len(taproot_seckeys) + len(plain_seckeys)) == 0:
        raise ValueError("At least one secret key must be provided.")
    for i in range(len(recipients)):
        if recipients[i].index != i:
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
    # calculate secret component of the shared secret
    secret_component = input_hash * seckey_sum

    # group recipients by scan public key
    recipients.sort(key=lambda r: r.scan_pubkey.to_bytes_compressed())

    # create outputs
    created_outputs = [None]*len(recipients)
    current_scan_pubkey = recipients[0].scan_pubkey
    k = 0
    for i in range(0, len(recipients)):
        if i == 0 or recipients[i].scan_pubkey != current_scan_pubkey:
            # if we are on a different scan pubkey, its time to recreate the shared secret and reset k to 0
            shared_secret = (secret_component * recipients[i].scan_pubkey).to_bytes_compressed()
            k = 0
        output_tweak = _create_output_tweak(shared_secret, k)
        output = recipients[i].spend_pubkey + output_tweak * G
        created_outputs[recipients[i].index] = output.to_bytes_xonly()
        k += 1
        current_scan_pubkey = recipients[i].scan_pubkey

    assert all([co is not None for co in created_outputs])
    return created_outputs


def silentpayments_recipient_create_label(scan_key: bytes, m: int) -> tuple[GE, Scalar]:
    label_tweak = Scalar.from_bytes(tagged_hash("BIP0352/Label", scan_key + m.to_bytes(4, 'big')))
    label = label_tweak * G
    return (label, label_tweak)


def silentpayments_recipient_create_labeled_spend_pubkey(unlabeled_spend_pubkey: GE, label: GE) -> GE:
    return unlabeled_spend_pubkey + label


def silentpayments_recipient_prevouts_summary_create(xonly_pubkeys: List[GE], plain_pubkeys: List[GE]) -> silentpayments_prevouts_summary:
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


# to keep it simple, the label lookup is hardcoded here and not passed as parameter
def silentpayments_recipient_scan_outputs(tx_outputs: List[bytes], scan_key: bytes,
                                          prevouts_summary: silentpayments_prevouts_summary, unlabeled_spend_pubkey: GE):
    # calculate the shared secret
    secret_component = prevouts_summary.input_hash * Scalar.from_bytes_checked(scan_key)
    shared_secret = secret_component * unlabeled_spend_pubkey

    found_idx = 0
    for k in range(0, len(tx_outputs)):
        tx_output_ge = GE.from_bytes_xonly(tx_outputs[k])
        output_tweak = _create_output_tweak(shared_secret, k)
    # TODO: finish
