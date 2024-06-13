from typing import List, Tuple

from electrumx.lib.util import (
    unpack_le_uint16_from,
    unpack_le_uint32_from,
    unpack_le_uint64_from,
)


def read_bytes(data, offset, length):
    if offset + length > len(data):
        raise IndexError(f"Offset out of range while reading bytes at offset {offset}")
    return data[offset : offset + length], offset + length


def find_tapleaf_scripts(inputs):
    tapleaf_scripts = []
    for input_map in inputs:
        for key, value in input_map.items():
            if key[0] == 0x15:  # 0x15 is the type for tapleaf scripts
                tapleaf_scripts.append(value)
    return tapleaf_scripts


def parse_psbt_hex_and_operations(psbt_hex: str) -> Tuple[str, List[bytes]]:
    """
    Parse the PSBT into raw TX, and resolves the optional Atomicals operations from Taproot Leaf scripts.
    :param psbt_hex: The PSBT text in hex format.
    :return: converted TX in hex format and optional Atomicals operations.
    """
    psbt_bytes = bytes.fromhex(psbt_hex)
    magic = psbt_bytes[:5]
    if magic != b"\x70\x73\x62\x74\xff":
        raise ValueError("Invalid PSBT magic bytes")

    offset = 5
    global_map = {}
    inputs = []
    outputs = []

    def read_varint(data, cursor):
        v = data[cursor]
        cursor += 1
        if v < 0xFD:
            return v, cursor
        elif v == 0xFD:
            return unpack_le_uint16_from(data, cursor)[0], cursor + 2
        elif v == 0xFE:
            return unpack_le_uint32_from(data, cursor)[0], cursor + 4
        else:
            return unpack_le_uint64_from(data, cursor)[0], cursor + 8

    while offset < len(psbt_bytes):
        key_len, offset = read_varint(psbt_bytes, offset)
        if key_len == 0:
            break
        key = psbt_bytes[offset : offset + key_len]
        offset += key_len
        value_len, offset = read_varint(psbt_bytes, offset)
        value = psbt_bytes[offset : offset + value_len]
        offset += value_len

        if key[0] == 0x00:
            global_map[key] = value
        elif key[0] == 0x01:
            inputs.append((key, value))
        elif key[0] == 0x02:
            outputs.append((key, value))

    unsigned_tx = global_map.get(b"\x00")
    if unsigned_tx is None:
        raise ValueError("No unsigned transaction found in PSBT")

    def parse_map(data, o):
        m = {}
        while o < len(data) and data[o] != 0x00:
            kl, o = read_varint(data, o)
            k, o = read_bytes(data, o, kl)
            vl, o = read_varint(data, o)
            v, o = read_bytes(data, o, vl)
            m[k] = v
        return m, o + 1

    input_count, offset_tx = read_varint(unsigned_tx, 4)
    offset_tx += 4

    for i in range(input_count):
        if offset >= len(psbt_bytes):
            raise IndexError(f"Offset out of range while parsing input map at index {i}")
        input_map, offset = parse_map(psbt_bytes, offset)
        inputs.append(input_map)

    tap_leafs = find_tapleaf_scripts(inputs)
    return unsigned_tx.hex(), tap_leafs
