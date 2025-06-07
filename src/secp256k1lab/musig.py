import secrets
from typing import List, NamedTuple, NewType, Optional, Tuple

from .bip340 import schnorr_verify
from .secp256k1 import FE, GE, G
from .util import int_from_bytes, bytes_from_int, xor_bytes, tagged_hash


PlainPk = NewType('PlainPk', bytes)
XonlyPk = NewType('XonlyPk', bytes)

# There are two types of exceptions that can be raised by this implementation:
#   - ValueError for indicating that an input doesn't conform to some function
#     precondition (e.g. an input array is the wrong length, a serialized
#     representation doesn't have the correct format).
#   - InvalidContributionError for indicating that a signer (or the
#     aggregator) is misbehaving in the protocol.
#
# Assertions are used to (1) satisfy the type-checking system, and (2) check for
# inconvenient events that can't happen except with negligible probability (e.g.
# output of a hash function is 0) and can't be manually triggered by any
# signer.

# This exception is raised if a party (signer or nonce aggregator) sends invalid
# values. Actual implementations should not crash when receiving invalid
# contributions. Instead, they should hold the offending party accountable.
class InvalidContributionError(Exception):
    def __init__(self, signer, contrib):
        self.signer = signer
        # contrib is one of "pubkey", "pubnonce", "aggnonce", or "psig".
        self.contrib = contrib


def key_sort(pubkeys: List[PlainPk]) -> List[PlainPk]:
    pubkeys.sort()
    return pubkeys

KeyAggContext = NamedTuple('KeyAggContext', [('Q', GE),
                                             ('gacc', int),
                                             ('tacc', int)])

def get_xonly_pk(keyagg_ctx: KeyAggContext) -> XonlyPk:
    Q, _, _ = keyagg_ctx
    return Q.to_bytes_xonly()

def key_agg(pubkeys: List[PlainPk]) -> KeyAggContext:
    pk2 = get_second_key(pubkeys)
    u = len(pubkeys)
    Q = GE()
    for i in range(u):
        try:
            P_i = GE.from_bytes_compressed(pubkeys[i])
        except ValueError:
            raise InvalidContributionError(i, "pubkey")
        a_i = key_agg_coeff_internal(pubkeys, pubkeys[i], pk2)
        Q = Q + a_i * P_i
    # Q is not the point at infinity except with negligible probability.
    assert not Q.infinity
    gacc = 1
    tacc = 0
    return KeyAggContext(Q, gacc, tacc)

def hash_keys(pubkeys: List[PlainPk]) -> bytes:
    return tagged_hash('KeyAgg list', b''.join(pubkeys))

def get_second_key(pubkeys: List[PlainPk]) -> PlainPk:
    u = len(pubkeys)
    for j in range(1, u):
        if pubkeys[j] != pubkeys[0]:
            return pubkeys[j]
    return PlainPk(b'\x00'*33)

def key_agg_coeff(pubkeys: List[PlainPk], pk_: PlainPk) -> int:
    pk2 = get_second_key(pubkeys)
    return key_agg_coeff_internal(pubkeys, pk_, pk2)

def key_agg_coeff_internal(pubkeys: List[PlainPk], pk_: PlainPk, pk2: PlainPk) -> int:
    L = hash_keys(pubkeys)
    if pk_ == pk2:
        return 1
    return int_from_bytes(tagged_hash('KeyAgg coefficient', L + pk_)) % GE.ORDER

def apply_tweak(keyagg_ctx: KeyAggContext, tweak: bytes, is_xonly: bool) -> KeyAggContext:
    if len(tweak) != 32:
        raise ValueError('The tweak must be a 32-byte array.')
    Q, gacc, tacc = keyagg_ctx
    if is_xonly and not Q.has_even_y():
        g = GE.ORDER - 1
    else:
        g = 1
    t = int_from_bytes(tweak)
    if t >= GE.ORDER:
        raise ValueError('The tweak must be less than n.')
    Q_ = g * Q + t * G
    if Q_.infinity:
        raise ValueError('The result of tweaking cannot be infinity.')
    # use secp256k1 Scalar?
    gacc_ = g * gacc % GE.ORDER
    tacc_ = (t + g * tacc) % GE.ORDER
    return KeyAggContext(Q_, gacc_, tacc_)

def nonce_hash(rand: bytes, pk: PlainPk, aggpk: XonlyPk, i: int, msg_prefixed: bytes, extra_in: bytes) -> int:
    buf = b''
    buf += rand
    buf += len(pk).to_bytes(1, 'big')
    buf += pk
    buf += len(aggpk).to_bytes(1, 'big')
    buf += aggpk
    buf += msg_prefixed
    buf += len(extra_in).to_bytes(4, 'big')
    buf += extra_in
    buf += i.to_bytes(1, 'big')
    return int_from_bytes(tagged_hash('MuSig/nonce', buf))

def nonce_gen_internal(rand_: bytes, sk: Optional[bytes], pk: PlainPk, aggpk: Optional[XonlyPk], msg: Optional[bytes], extra_in: Optional[bytes]) -> Tuple[bytearray, bytes]:
    if sk is not None:
        rand = xor_bytes(sk, tagged_hash('MuSig/aux', rand_))
    else:
        rand = rand_
    if aggpk is None:
        aggpk = XonlyPk(b'')
    if msg is None:
        msg_prefixed = b'\x00'
    else:
        msg_prefixed = b'\x01'
        msg_prefixed += len(msg).to_bytes(8, 'big')
        msg_prefixed += msg
    if extra_in is None:
        extra_in = b''
    k_1 = nonce_hash(rand, pk, aggpk, 0, msg_prefixed, extra_in) % GE.ORDER
    k_2 = nonce_hash(rand, pk, aggpk, 1, msg_prefixed, extra_in) % GE.ORDER
    # k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    assert k_1 != 0
    assert k_2 != 0
    R_s1 = k_1 * G
    R_s2 = k_2 * G
    assert not R_s1.infinity
    assert not R_s2.infinity
    pubnonce = R_s1.to_bytes_compressed() + R_s2.to_bytes_compressed()
    secnonce = bytearray(bytes_from_int(k_1) + bytes_from_int(k_2) + pk)
    return secnonce, pubnonce

def nonce_gen(sk: Optional[bytes], pk: PlainPk, aggpk: Optional[XonlyPk], msg: Optional[bytes], extra_in: Optional[bytes]) -> Tuple[bytearray, bytes]:
    if sk is not None and len(sk) != 32:
        raise ValueError('The optional byte array sk must have length 32.')
    if aggpk is not None and len(aggpk) != 32:
        raise ValueError('The optional byte array aggpk must have length 32.')
    rand_ = secrets.token_bytes(32)
    return nonce_gen_internal(rand_, sk, pk, aggpk, msg, extra_in)

def nonce_agg(pubnonces: List[bytes]) -> bytes:
    u = len(pubnonces)
    aggnonce = b''
    for j in (1, 2):
        R_j = GE()
        for i in range(u):
            try:
                R_ij = GE.from_bytes_compressed(pubnonces[i][(j-1)*33:j*33])
            except ValueError:
                raise InvalidContributionError(i, "pubnonce")
            R_j = R_j + R_ij
        aggnonce += R_j.to_bytes_compressed_with_infinity()
    return aggnonce

SessionContext = NamedTuple('SessionContext', [('aggnonce', bytes),
                                               ('pubkeys', List[PlainPk]),
                                               ('tweaks', List[bytes]),
                                               ('is_xonly', List[bool]),
                                               ('msg', bytes)])

def key_agg_and_tweak(pubkeys: List[PlainPk], tweaks: List[bytes], is_xonly: List[bool]) -> KeyAggContext:
    if len(tweaks) != len(is_xonly):
        raise ValueError('The `tweaks` and `is_xonly` arrays must have the same length.')
    keyagg_ctx = key_agg(pubkeys)
    v = len(tweaks)
    for i in range(v):
        keyagg_ctx = apply_tweak(keyagg_ctx, tweaks[i], is_xonly[i])
    return keyagg_ctx

def get_session_values(session_ctx: SessionContext) -> Tuple[GE, int, int, int, GE, int]:
    (aggnonce, pubkeys, tweaks, is_xonly, msg) = session_ctx
    Q, gacc, tacc = key_agg_and_tweak(pubkeys, tweaks, is_xonly)
    b = int_from_bytes(tagged_hash('MuSig/noncecoef', aggnonce + Q.to_bytes_xonly() + msg)) % GE.ORDER
    try:
        R_1 = GE.from_bytes_compressed_with_infinity(aggnonce[0:33])
        R_2 = GE.from_bytes_compressed_with_infinity(aggnonce[33:66])
    except ValueError:
        # Nonce aggregator sent invalid nonces
        raise InvalidContributionError(None, "aggnonce")
    R_ = R_1 + b * R_2
    R = R_ if not R_.infinity else G
    assert not R.infinity
    e = int_from_bytes(tagged_hash('BIP0340/challenge', R.to_bytes_xonly() + Q.to_bytes_xonly() + msg)) % GE.ORDER
    return (Q, gacc, tacc, b, R, e)

def get_session_key_agg_coeff(session_ctx: SessionContext, P: GE) -> int:
    (_, pubkeys, _, _, _) = session_ctx
    pk = PlainPk(P.to_bytes_compressed())
    if pk not in pubkeys:
        raise ValueError('The signer\'s pubkey must be included in the list of pubkeys.')
    return key_agg_coeff(pubkeys, pk)

def sign(secnonce: bytearray, sk: bytes, session_ctx: SessionContext) -> bytes:
    (Q, gacc, _, b, R, e) = get_session_values(session_ctx)
    k_1_ = int_from_bytes(secnonce[0:32])
    k_2_ = int_from_bytes(secnonce[32:64])
    # Overwrite the secnonce argument with zeros such that subsequent calls of
    # sign with the same secnonce raise a ValueError.
    secnonce[:64] = bytearray(b'\x00'*64)
    if not 0 < k_1_ < GE.ORDER:
        raise ValueError('first secnonce value is out of range.')
    if not 0 < k_2_ < GE.ORDER:
        raise ValueError('second secnonce value is out of range.')
    k_1 = k_1_ if R.has_even_y() else GE.ORDER - k_1_
    k_2 = k_2_ if R.has_even_y() else GE.ORDER - k_2_
    d_ = int_from_bytes(sk)
    if not 0 < d_ < GE.ORDER:
        raise ValueError('secret key value is out of range.')
    P = d_ * G
    assert not P.infinity
    pk = P.to_bytes_compressed()
    if not pk == secnonce[64:97]:
        raise ValueError('Public key does not match nonce_gen argument')
    a = get_session_key_agg_coeff(session_ctx, P)
    g = 1 if Q.has_even_y() else GE.ORDER - 1
    d = g * gacc * d_ % GE.ORDER
    s = (k_1 + b * k_2 + e * a * d) % GE.ORDER
    psig = bytes_from_int(s)
    R_s1 = k_1_ * G
    R_s2 = k_2_ * G
    assert not R_s1.infinity
    assert not R_s2.infinity
    pubnonce = R_s1.to_bytes_compressed() + R_s2.to_bytes_compressed()
    # Optional correctness check. The result of signing should pass signature verification.
    assert partial_sig_verify_internal(psig, pubnonce, pk, session_ctx)
    return psig

def det_nonce_hash(sk_: bytes, aggothernonce: bytes, aggpk: bytes, msg: bytes, i: int) -> int:
    buf = b''
    buf += sk_
    buf += aggothernonce
    buf += aggpk
    buf += len(msg).to_bytes(8, 'big')
    buf += msg
    buf += i.to_bytes(1, 'big')
    return int_from_bytes(tagged_hash('MuSig/deterministic/nonce', buf))

def deterministic_sign(sk: bytes, aggothernonce: bytes, pubkeys: List[PlainPk], tweaks: List[bytes], is_xonly: List[bool], msg: bytes, rand: Optional[bytes]) -> Tuple[bytes, bytes]:
    if rand is not None:
        sk_ = bytes_xor(sk, tagged_hash('MuSig/aux', rand))
    else:
        sk_ = sk
    aggpk = get_xonly_pk(key_agg_and_tweak(pubkeys, tweaks, is_xonly))

    k_1 = det_nonce_hash(sk_, aggothernonce, aggpk, msg, 0) % GE.ORDER
    k_2 = det_nonce_hash(sk_, aggothernonce, aggpk, msg, 1) % GE.ORDER
    # k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    assert k_1 != 0
    assert k_2 != 0

    R_s1 = k_1 * G
    R_s2 = k_2 * G
    assert not R_s1.infinity
    assert not R_s2.infinity
    pubnonce = R_s1.to_bytes_compressed() + R_s2.to_bytes_compressed()
    secnonce = bytearray(bytes_from_int(k_1) + bytes_from_int(k_2) + individual_pk(sk))
    try:
        aggnonce = nonce_agg([pubnonce, aggothernonce])
    except Exception:
        raise InvalidContributionError(None, "aggothernonce")
    session_ctx = SessionContext(aggnonce, pubkeys, tweaks, is_xonly, msg)
    psig = sign(secnonce, sk, session_ctx)
    return (pubnonce, psig)

def partial_sig_verify(psig: bytes, pubnonces: List[bytes], pubkeys: List[PlainPk], tweaks: List[bytes], is_xonly: List[bool], msg: bytes, i: int) -> bool:
    if len(pubnonces) != len(pubkeys):
        raise ValueError('The `pubnonces` and `pubkeys` arrays must have the same length.')
    if len(tweaks) != len(is_xonly):
        raise ValueError('The `tweaks` and `is_xonly` arrays must have the same length.')
    aggnonce = nonce_agg(pubnonces)
    session_ctx = SessionContext(aggnonce, pubkeys, tweaks, is_xonly, msg)
    return partial_sig_verify_internal(psig, pubnonces[i], pubkeys[i], session_ctx)

def partial_sig_verify_internal(psig: bytes, pubnonce: bytes, pk: bytes, session_ctx: SessionContext) -> bool:
    (Q, gacc, _, b, R, e) = get_session_values(session_ctx)
    s = int_from_bytes(psig)
    if s >= GE.ORDER:
        return False
    R_s1 = GE.from_bytes_compressed(pubnonce[0:33])
    R_s2 = GE.from_bytes_compressed(pubnonce[33:66])
    Re_s_ = R_s1 + b * R_s2
    Re_s = Re_s_ if R.has_even_y() else -Re_s_
    P = GE.from_bytes_compressed(pk)
    a = get_session_key_agg_coeff(session_ctx, P)
    g = 1 if Q.has_even_y() else GE.ORDER - 1
    g_ = g * gacc % GE.ORDER
    return s * G == Re_s + (e * a * g_ % GE.ORDER) * P

def partial_sig_agg(psigs: List[bytes], session_ctx: SessionContext) -> bytes:
    (Q, _, tacc, _, R, e) = get_session_values(session_ctx)
    s = 0
    u = len(psigs)
    for i in range(u):
        s_i = int_from_bytes(psigs[i])
        if s_i >= GE.ORDER:
            raise InvalidContributionError(i, "psig")
        s = (s + s_i) % GE.ORDER
    g = 1 if Q.has_even_y() else GE.ORDER - 1
    s = (s + e * g * tacc) % GE.ORDER
    return R.to_bytes_xonly() + bytes_from_int(s)
