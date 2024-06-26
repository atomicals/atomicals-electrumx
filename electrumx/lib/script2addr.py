import hashlib
import os
import struct
from typing import Callable, Optional, Union

from electrumx.lib import segwit_addr
from electrumx.lib.script import OpCodes


class MalformedBitcoinScript(Exception):
    pass


def script_GetOp(_bytes: bytes):
    i = 0
    while i < len(_bytes):
        vch = None
        opcode = _bytes[i]
        i += 1
        if opcode <= OpCodes.OP_PUSHDATA4:
            nSize = opcode
            if opcode == OpCodes.OP_PUSHDATA1:
                try:
                    nSize = _bytes[i]
                except IndexError:
                    raise MalformedBitcoinScript()
                i += 1
            elif opcode == OpCodes.OP_PUSHDATA2:
                try:
                    (nSize,) = struct.unpack_from("<H", _bytes, i)
                except struct.error:
                    raise MalformedBitcoinScript()
                i += 2
            elif opcode == OpCodes.OP_PUSHDATA4:
                try:
                    (nSize,) = struct.unpack_from("<I", _bytes, i)
                except struct.error:
                    raise MalformedBitcoinScript()
                i += 4
            vch = _bytes[i : i + nSize]
            i += nSize

        yield opcode, vch, i


class OPPushDataGeneric:
    def __init__(self, pushlen: Callable = None):
        if pushlen is not None:
            self.check_data_len = pushlen

    @classmethod
    def check_data_len(cls, datalen: int) -> bool:
        # Opcodes below OP_PUSHDATA4 all just push data onto stack, and are equivalent.
        return OpCodes.OP_PUSHDATA4 >= datalen >= 0

    @classmethod
    def is_instance(cls, item):
        # accept objects that are instances of this class
        # or other classes that are subclasses
        return isinstance(item, cls) or (isinstance(item, type) and issubclass(item, cls))


class OPGeneric:
    def __init__(self, matcher: Callable = None):
        if matcher is not None:
            self.matcher = matcher

    def match(self, op) -> bool:
        return self.matcher(op)

    @classmethod
    def is_instance(cls, item):
        # accept objects that are instances of this class
        # or other classes that are subclasses
        return isinstance(item, cls) or (isinstance(item, type) and issubclass(item, cls))


def match_script_against_template(script, template) -> bool:
    """Returns whether 'script' matches 'template'."""
    if script is None:
        return False
    # optionally decode script now:
    if isinstance(script, (bytes, bytearray)):
        try:
            script = [x for x in script_GetOp(script)]
        except MalformedBitcoinScript:
            return False

    if len(script) != len(template):
        return False
    for i in range(len(script)):
        template_item = template[i]
        script_item = script[i]
        if OPPushDataGeneric.is_instance(template_item) and template_item.check_data_len(script_item[0]):
            continue
        if OPGeneric.is_instance(template_item) and template_item.match(script_item[0]):
            continue
        if template_item != script_item[0]:
            return False
    return True


OP_ANYSEGWIT_VERSION = OPGeneric(lambda x: x in list(range(OpCodes.OP_1, OpCodes.OP_16 + 1)))

SCRIPTPUBKEY_TEMPLATE_P2PKH = [
    OpCodes.OP_DUP,
    OpCodes.OP_HASH160,
    OPPushDataGeneric(lambda x: x == 20),
    OpCodes.OP_EQUALVERIFY,
    OpCodes.OP_CHECKSIG,
]
SCRIPTPUBKEY_TEMPLATE_P2SH = [
    OpCodes.OP_HASH160,
    OPPushDataGeneric(lambda x: x == 20),
    OpCodes.OP_EQUAL,
]
SCRIPTPUBKEY_TEMPLATE_WITNESS_V0 = [
    OpCodes.OP_0,
    OPPushDataGeneric(lambda x: x in (20, 32)),
]
SCRIPTPUBKEY_TEMPLATE_P2WPKH = [OpCodes.OP_0, OPPushDataGeneric(lambda x: x == 20)]
SCRIPTPUBKEY_TEMPLATE_P2WSH = [OpCodes.OP_0, OPPushDataGeneric(lambda x: x == 32)]
SCRIPTPUBKEY_TEMPLATE_ANYSEGWIT = [
    OP_ANYSEGWIT_VERSION,
    OPPushDataGeneric(lambda x: x in list(range(2, 40 + 1))),
]


def sha256(x: Union[bytes, str]) -> bytes:
    x = to_bytes(x, "utf8")
    return bytes(hashlib.sha256(x).digest())


def to_bytes(something, encoding="utf8") -> bytes:
    """
    cast string to bytes() like object, but for python2 support it's bytearray copy
    """
    if isinstance(something, bytes):
        return something
    if isinstance(something, str):
        return something.encode(encoding)
    elif isinstance(something, bytearray):
        return bytes(something)
    else:
        raise TypeError("Not a string or bytes like object")


def sha256d(x: Union[bytes, str]) -> bytes:
    x = to_bytes(x, "utf8")
    out = bytes(sha256(sha256(x)))
    return out


def assert_bytes(*args):
    """
    porting helper, assert args type
    """
    try:
        for x in args:
            assert isinstance(x, (bytes, bytearray))
    except Exception:
        print("assert bytes failed", list(map(type, args)))
        raise


__b58chars = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
assert len(__b58chars) == 58

__b43chars = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:"
assert len(__b43chars) == 43


def base_encode(v: bytes, *, base: int) -> str:
    """encode v, which is a string of bytes, to base58."""
    assert_bytes(v)
    if base not in (58, 43):
        raise ValueError("not supported base: {}".format(base))
    chars = __b58chars
    if base == 43:
        chars = __b43chars

    origlen = len(v)
    v = v.lstrip(b"\x00")
    newlen = len(v)

    num = int.from_bytes(v, byteorder="big")
    string = b""
    while num:
        num, idx = divmod(num, base)
        string = chars[idx : idx + 1] + string

    result = chars[0:1] * (origlen - newlen) + string
    return result.decode("ascii")


def hash160_to_b58_address(h160: bytes, addrtype: int) -> str:
    s = bytes([addrtype]) + h160
    s = s + sha256d(s)[0:4]
    return base_encode(s, base=58)


def ripemd(x: bytes) -> bytes:
    try:
        md = hashlib.new("ripemd160")
        md.update(x)
        return md.digest()
    except BaseException:
        # ripemd160 is not guaranteed to be available in hashlib on all platforms.
        # Historically, our Android builds had hashlib/openssl which did not have it.
        # see https://github.com/spesmilo/electrum/issues/7093
        # We bundle a pure python implementation as fallback that gets used now:
        from . import ripemd

        md = ripemd.new(x)
        return md.digest()


def hash_160(x: bytes) -> bytes:
    return ripemd(sha256(x))


def hash160_to_p2pkh(h160: bytes) -> str:
    return hash160_to_b58_address(h160, get_addr_type_p2pkh())


def hash160_to_p2sh(h160: bytes) -> str:
    return hash160_to_b58_address(h160, get_addr_type_p2sh())


def public_key_to_p2pkh(public_key: bytes) -> str:
    return hash160_to_p2pkh(hash_160(public_key))


def hash_to_segwit_addr(h: bytes, witver: int) -> str:
    addr = segwit_addr.encode(get_segwit_hrp(), witver, h)
    assert addr is not None
    return addr


def get_net_from_env():
    if "NET" in os.environ:
        return os.environ["NET"]
    return "mainnet"


def get_addr_type_p2pkh():
    net = get_net_from_env()
    value = 0  # mainnet
    if net == "testnet" or net == "testnet4":
        value = 111
    elif net == "regtest":
        value = 111
    return value


def get_addr_type_p2sh():
    net = get_net_from_env()
    value = 5  # mainnet
    if net == "testnet" or net == "testnet4":
        value = 196
    elif net == "regtest":
        value = 196
    return value


def get_segwit_hrp():
    net = get_net_from_env()
    value = "bc"  # mainnet
    if net == "testnet" or net == "testnet4":
        value = "tb"
    elif net == "regtest":
        value = "bcrt"
    return value


def get_address_from_output_script(_bytes: bytes) -> Optional[str]:
    try:
        decoded = [x for x in script_GetOp(_bytes)]
    except MalformedBitcoinScript:
        return None
    # p2pkh
    if match_script_against_template(decoded, SCRIPTPUBKEY_TEMPLATE_P2PKH):
        return hash160_to_p2pkh(decoded[2][1])

    # p2sh
    if match_script_against_template(decoded, SCRIPTPUBKEY_TEMPLATE_P2SH):
        return hash160_to_p2sh(decoded[1][1])

    # segwit address (version 0)
    if match_script_against_template(decoded, SCRIPTPUBKEY_TEMPLATE_WITNESS_V0):
        return hash_to_segwit_addr(decoded[1][1], witver=0)

    # segwit address (version 1-16)
    future_witness_versions = list(range(OpCodes.OP_1, OpCodes.OP_16 + 1))
    for witver, opcode in enumerate(future_witness_versions, start=1):
        match = [opcode, OPPushDataGeneric(lambda x: 2 <= x <= 40)]
        if match_script_against_template(decoded, match):
            return hash_to_segwit_addr(decoded[1][1], witver=witver)

    return None
