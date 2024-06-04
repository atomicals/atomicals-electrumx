from aiorpcx import RPCError

from electrumx.lib.hash import HASHX_LEN, hex_str_to_hash
from electrumx.server.session import BAD_REQUEST

SESSION_BASE_MAX_CHUNK_SIZE = 2016
SESSION_PROTOCOL_MIN = (1, 4)
SESSION_PROTOCOL_MAX = (1, 4, 3)


def scripthash_to_hash_x(scripthash):
    try:
        bin_hash = hex_str_to_hash(scripthash)
        if len(bin_hash) == 32:
            return bin_hash[:HASHX_LEN]
    except (ValueError, TypeError):
        pass
    raise RPCError(BAD_REQUEST, f"{scripthash} is not a valid script hash")


def non_negative_integer(value):
    """Return param value it is or can be converted to a non-negative
    integer, otherwise raise an RPCError."""
    try:
        value = int(value)
        if value >= 0:
            return value
    except (ValueError, TypeError):
        pass
    raise RPCError(BAD_REQUEST, f"{value} should be a non-negative integer")


def assert_tx_hash(value):
    """Raise an RPCError if the value is not a valid hexadecimal transaction hash.

    If it is valid, return it as 32-byte binary hash."""
    try:
        raw_hash = hex_str_to_hash(value)
        if len(raw_hash) == 32:
            return raw_hash
    except (ValueError, TypeError):
        pass
    raise RPCError(BAD_REQUEST, f"{value} should be a transaction hash")


def assert_atomical_id(value):
    """Raise an RPCError if the value is not a valid atomical id
    If it is valid, return it as 32-byte binary hash."""
    try:
        if value is None or value == "":
            raise RPCError(BAD_REQUEST, f"atomical_id required")
        index_of_i = value.find("i")
        if index_of_i != 64:
            raise RPCError(BAD_REQUEST, f"{value} should be an atomical_id")
        raw_hash = hex_str_to_hash(value[:64])
        if len(raw_hash) == 32:
            return raw_hash
    except (ValueError, TypeError):
        pass

    raise RPCError(BAD_REQUEST, f"{value} should be an atomical_id")
