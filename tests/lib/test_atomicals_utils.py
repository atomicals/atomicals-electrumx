import pytest

from electrumx.lib.coins import Bitcoin
from electrumx.lib.hash import hex_str_to_hash
from electrumx.lib.util_atomicals import (
    MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS,
    calculate_expected_bitwork,
    decode_bitwork_target_from_prefix,
    derive_bitwork_prefix_from_target,
    get_next_bitwork_full_str,
    is_bitwork_subset,
    is_txid_valid_for_perpetual_bitwork,
)

coin = Bitcoin

MAX_BLOCKS_STR = str(MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS)


class MockLogger:
    def debug(self, msg):
        return

    def info(self, msg):
        return

    def warning(self, msg):
        return


def test_derive_bitwork_prefix_from_target_exception():
    with pytest.raises(Exception):
        derive_bitwork_prefix_from_target("", 0)
        derive_bitwork_prefix_from_target("", 15)


def test_derive_bitwork_prefix_from_target_from_empty():
    testvec = [
        {"base": "", "inc": 16, "exp": "0"},
        {"base": "", "inc": 17, "exp": "0.1"},
        {"base": "", "inc": 18, "exp": "0.2"},
        {"base": "", "inc": 19, "exp": "0.3"},
        {"base": "", "inc": 20, "exp": "0.4"},
        {"base": "", "inc": 21, "exp": "0.5"},
        {"base": "", "inc": 22, "exp": "0.6"},
        {"base": "", "inc": 23, "exp": "0.7"},
        {"base": "", "inc": 24, "exp": "0.8"},
        {"base": "", "inc": 25, "exp": "0.9"},
        {"base": "", "inc": 26, "exp": "0.10"},
        {"base": "", "inc": 27, "exp": "0.11"},
        {
            "base": "",
            "inc": 28,
            "exp": "0.12",
        },
        {"base": "", "inc": 29, "exp": "0.13"},
        {"base": "", "inc": 30, "exp": "0.14"},
        {"base": "", "inc": 31, "exp": "0.15"},
        {"base": "", "inc": 32, "exp": "00"},
        {"base": "", "inc": 33, "exp": "00.1"},
        {"base": "", "inc": 34, "exp": "00.2"},
        {"base": "", "inc": 35, "exp": "00.3"},
        {"base": "", "inc": 36, "exp": "00.4"},
        {"base": "", "inc": 37, "exp": "00.5"},
        {"base": "", "inc": 38, "exp": "00.6"},
        {"base": "", "inc": 39, "exp": "00.7"},
        {"base": "", "inc": 40, "exp": "00.8"},
        {"base": "", "inc": 41, "exp": "00.9"},
        {"base": "", "inc": 42, "exp": "00.10"},
        {"base": "", "inc": 43, "exp": "00.11"},
        {"base": "", "inc": 44, "exp": "00.12"},
        {"base": "", "inc": 45, "exp": "00.13"},
        {"base": "", "inc": 46, "exp": "00.14"},
        {"base": "", "inc": 47, "exp": "00.15"},
        {"base": "", "inc": 48, "exp": "000"},
        {"base": "", "inc": 49, "exp": "000.1"},
        {"base": "", "inc": 50, "exp": "000.2"},
        {"base": "", "inc": 51, "exp": "000.3"},
        {"base": "", "inc": 52, "exp": "000.4"},
        {"base": "", "inc": 53, "exp": "000.5"},
        {"base": "", "inc": 54, "exp": "000.6"},
        {"base": "", "inc": 55, "exp": "000.7"},
        {"base": "", "inc": 56, "exp": "000.8"},
        {"base": "", "inc": 57, "exp": "000.9"},
        {"base": "", "inc": 58, "exp": "000.10"},
        {"base": "", "inc": 59, "exp": "000.11"},
        {"base": "", "inc": 60, "exp": "000.12"},
        {"base": "", "inc": 61, "exp": "000.13"},
        {"base": "", "inc": 62, "exp": "000.14"},
        {"base": "", "inc": 63, "exp": "000.15"},
        {"base": "", "inc": 64, "exp": "0000"},
        {"base": "", "inc": 65, "exp": "0000.1"},
    ]

    for x in testvec:
        assert derive_bitwork_prefix_from_target(x["base"], x["inc"]) == x["exp"]


def test_derive_bitwork_prefix_from_target_misc():
    testvec = [
        {"base": "abc", "inc": 64, "exp": "abc0"},
        {"base": "abcd", "inc": 64, "exp": "abcd"},
        {"base": "abcd", "inc": 65, "exp": "abcd.1"},
        {"base": "abcd", "inc": 80, "exp": "abcd0"},
        {"base": "abcd", "inc": 83, "exp": "abcd0.3"},
        {"base": "0123456789abcdef", "inc": 128, "exp": "01234567"},
        {"base": "0123456789abcdef", "inc": 129, "exp": "01234567.1"},
        {"base": "0123456789abcdef", "inc": 256, "exp": "0123456789abcdef"},
        {"base": "0123456789abcdef", "inc": 257, "exp": "0123456789abcdef.1"},
        {"base": "0123456789abcdef", "inc": 273, "exp": "0123456789abcdef0.1"},
    ]

    for x in testvec:
        assert derive_bitwork_prefix_from_target(x["base"], x["inc"]) == x["exp"]


def test_decode_bitwork_target_from_prefix_empty():
    with pytest.raises(Exception):
        decode_bitwork_target_from_prefix("z")
    with pytest.raises(Exception):
        decode_bitwork_target_from_prefix(".")
    with pytest.raises(Exception):
        decode_bitwork_target_from_prefix("0.")
    with pytest.raises(Exception):
        decode_bitwork_target_from_prefix("0.17")
    with pytest.raises(Exception):
        decode_bitwork_target_from_prefix("")
    with pytest.raises(Exception):
        decode_bitwork_target_from_prefix("00..0")


def test_decode_bitwork_target_from_prefix_valid():
    testvec = [
        {"bitwork": "a", "target": 16},
        {"bitwork": "a.0", "target": 16},
        {"bitwork": "a.1", "target": 17},
        {"bitwork": "a.2", "target": 18},
        {"bitwork": "a.15", "target": 31},
        {"bitwork": "ab", "target": 32},
        {"bitwork": "ab.0", "target": 32},
        {"bitwork": "abcd", "target": 64},
        {"bitwork": "abcd.1", "target": 65},
        {"bitwork": "abcd0123", "target": 128},
        {"bitwork": "abcd0123.5", "target": 133},
    ]

    for x in testvec:
        assert decode_bitwork_target_from_prefix(x["bitwork"]) == x["target"]


def test_is_bitwork_subset_fail():
    with pytest.raises(Exception):
        is_bitwork_subset("", "")

    assert is_bitwork_subset("a", "b") == False
    assert is_bitwork_subset("a", "a") == True
    assert is_bitwork_subset("a", "ab") == True
    assert is_bitwork_subset("a", "a.1") == True
    assert is_bitwork_subset("ab", "ab") == True
    assert is_bitwork_subset("ab", "ab.1") == True
    assert is_bitwork_subset("ab.1", "ab.2") == True
    assert is_bitwork_subset("ab.14", "ab.15") == True
    assert is_bitwork_subset("ab.15", "ab0") == True
    assert is_bitwork_subset("ab", "ab") == True
    assert is_bitwork_subset("ab", "ab.15") == True
    assert is_bitwork_subset("ab.15", "ab") == False
    assert is_bitwork_subset("0000", "000") == False
    assert is_bitwork_subset("0000", "0000") == True
    assert is_bitwork_subset("0000", "00000") == True
    assert is_bitwork_subset("0000.5", "0000.6") == True
    assert is_bitwork_subset("0000.5", "0000.15") == True
    assert is_bitwork_subset("0000.5", "00008888") == True


def test_calculate_expected_bitwork_base():
    with pytest.raises(Exception):
        calculate_expected_bitwork("", 0, 1, 1, 63)

    with pytest.raises(Exception):
        calculate_expected_bitwork("", 0, 1, 0, 64)

    assert calculate_expected_bitwork("", 0, 1, 1, 64) == "0000"
    assert calculate_expected_bitwork("a", 0, 1, 1, 64) == "a000"
    assert calculate_expected_bitwork("a", 1, 1, 1, 64) == "a000.1"
    assert calculate_expected_bitwork("a", 2, 1, 1, 64) == "a000.2"
    assert calculate_expected_bitwork("a", 2, 1, 2, 64) == "a000.4"
    assert calculate_expected_bitwork("abcd", 0, 1000, 1, 64) == "abcd"
    assert calculate_expected_bitwork("abcd", 1, 1000, 1, 64) == "abcd"
    assert calculate_expected_bitwork("abcd", 999, 1000, 1, 64) == "abcd"
    assert calculate_expected_bitwork("abcd", 1000, 1000, 1, 64) == "abcd.1"
    assert calculate_expected_bitwork("abcd", 1001, 1000, 1, 64) == "abcd.1"
    assert calculate_expected_bitwork("abcd", 1999, 1000, 1, 64) == "abcd.1"
    assert calculate_expected_bitwork("abcd", 2000, 1000, 1, 64) == "abcd.2"
    assert calculate_expected_bitwork("abcd", 15999, 1000, 1, 64) == "abcd.15"
    assert calculate_expected_bitwork("abcd", 16000, 1000, 1, 64) == "abcd0"
    assert calculate_expected_bitwork("abcd", 16001, 1000, 1, 64) == "abcd0"
    assert calculate_expected_bitwork("abcdef", 32000, 1000, 1, 64) == "abcdef"
    assert calculate_expected_bitwork("abcdefe", 32001, 1000, 2, 64) == "abcdefe0"
    assert calculate_expected_bitwork("abcdefe", 33000, 1000, 2, 64) == "abcdefe0.2"
    assert calculate_expected_bitwork("abcdefe", 33000, 1000, 3, 64) == "abcdefe000.3"
    assert calculate_expected_bitwork("abcdefe", 33000, 1000, 1, 127) == "abcdefe000"
    assert calculate_expected_bitwork("abcdefe", 33000, 1000, 3, 127) == "abcdefe0000000.2"


def test_calculate_expected_bitwork_rollover():
    assert calculate_expected_bitwork("888888888888", 49995, 3333, 1, 64) == "8888.15"
    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        49995,
        3333,
        1,
        64,
        False,
    )
    assert not success
    assert not bitwork_str

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        49995,
        3333,
        1,
        64,
        True,
    )
    assert success
    assert bitwork_str == "88888"

    assert calculate_expected_bitwork("888888888888", 53189, 3333, 1, 64) == "8888.15"
    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        53189,
        3333,
        1,
        64,
        True,
    )
    assert success
    assert bitwork_str == "88888"

    assert calculate_expected_bitwork("888888888888", 53328, 3333, 1, 64) == "88888"
    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        53328,
        3333,
        1,
        64,
        False,
    )
    assert success
    assert bitwork_str == "88888"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        53328,
        3333,
        1,
        64,
        True,
    )
    assert success
    assert bitwork_str == "88888"

    assert calculate_expected_bitwork("888888888888", 53329, 3333, 1, 64) == "88888"
    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        53329,
        3333,
        1,
        64,
        False,
    )
    assert success
    assert bitwork_str == "88888"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        53329,
        3333,
        1,
        64,
        True,
    )
    assert success
    assert bitwork_str == "88888"

    assert calculate_expected_bitwork("888888888888", 53328 + 3333, 3333, 1, 64) == "88888.1"
    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        53328 + 3333,
        3333,
        1,
        64,
        False,
    )
    assert success
    assert bitwork_str == "88888.1"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        53328 + 3333,
        3333,
        1,
        64,
        True,
    )
    assert success
    assert bitwork_str == "88888.1"

    assert calculate_expected_bitwork("888888888888", 53328 + (3333 * 16) - 1, 3333, 1, 64) == "88888.15"
    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        53328 + (3333 * 16) - 1,
        3333,
        1,
        64,
        False,
    )
    assert not success
    assert not bitwork_str

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("88888f8888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        53328 + (3333 * 16) - 1,
        3333,
        1,
        64,
        False,
    )
    assert success
    assert bitwork_str == "88888.15"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("88888f8888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        53328 + (3333 * 16) - 1,
        3333,
        1,
        64,
        True,
    )
    assert success
    assert bitwork_str == "88888.15"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        53328 + (3333 * 16) - 1,
        3333,
        1,
        64,
        False,
    )
    assert not success
    assert not bitwork_str

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        53328 + (3333 * 16) - 1,
        3333,
        1,
        64,
        True,
    )
    assert success
    assert bitwork_str == "888888"

    assert calculate_expected_bitwork("888888888888", 999, 1000, 64, 64) == "8888"
    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        999,
        1000,
        64,
        64,
        False,
    )
    assert success
    assert bitwork_str == "8888"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("888f888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        999,
        1000,
        64,
        64,
        False,
    )
    assert not success

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("888f888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        999,
        1000,
        64,
        64,
        True,
    )
    assert not success

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888f88888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        999,
        1000,
        64,
        64,
        True,
    )
    assert success
    assert bitwork_str == "8888"

    assert calculate_expected_bitwork("888888888888", 1000, 1000, 64, 64) == "88888888"
    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        1000,
        1000,
        64,
        64,
        False,
    )
    assert success
    assert bitwork_str == "88888888"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("88888888f8888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        1000,
        1000,
        64,
        64,
        False,
    )
    assert success
    assert bitwork_str == "88888888"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("88888888f8888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        1000,
        1000,
        64,
        64,
        True,
    )
    assert success
    assert bitwork_str == "88888888"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888f88888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        1000,
        1000,
        64,
        64,
        True,
    )
    assert not success

    assert calculate_expected_bitwork("888888888888", 1000, 1000, 49, 64) == "8888888.1"
    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        1000,
        1000,
        49,
        64,
        False,
    )
    assert success
    assert bitwork_str == "8888888.1"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("88888888f8888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        1000,
        1000,
        49,
        64,
        False,
    )
    assert success
    assert bitwork_str == "8888888.1"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("88888888f8888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        1000,
        1000,
        49,
        64,
        True,
    )
    assert success
    assert bitwork_str == "8888888.1"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888088888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        1000,
        1000,
        49,
        64,
        True,
    )
    assert not success


def test_calculate_expected_bitwork_rollover2():
    assert calculate_expected_bitwork("888888888888", 3, 1, 5, 64) == "8888.15"
    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        3,
        1,
        5,
        64,
        False,
    )
    assert not success

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888888888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        3,
        1,
        5,
        64,
        True,
    )
    assert success
    assert bitwork_str == "88888"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888f88888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        3,
        1,
        5,
        64,
        True,
    )
    assert success
    assert bitwork_str == "8888.15"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888848888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        3,
        1,
        5,
        64,
        False,
    )
    assert not success

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888848888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        3,
        1,
        5,
        64,
        True,
    )
    assert success
    assert bitwork_str == "88888"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888858888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        3,
        1,
        5,
        64,
        True,
    )
    assert success
    assert bitwork_str == "88888"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888388888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        3,
        1,
        5,
        64,
        True,
    )
    assert not success

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("8888838888888888888888888888888888888888888888888888888888888888"),
        "888888888888",
        3,
        1,
        5,
        64,
        True,
    )
    assert success
    assert bitwork_str == "88888"


def test_calculate_expected_bitwork_rollover3():
    assert calculate_expected_bitwork("0a2f", 3, 1, 5, 64) == "0a2f.15"
    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("0a2f888888888888888888888888888888888888888888888888888888888888"),
        "0a2f",
        3,
        1,
        5,
        64,
        False,
    )
    assert not success

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("0a2f088888888888888888888888888888888888888888888888888888888888"),
        "0a2f",
        3,
        1,
        5,
        64,
        True,
    )
    assert success
    assert bitwork_str == "0a2f0"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("0a2ff88888888888888888888888888888888888888888888888888888888888"),
        "0a2f",
        3,
        1,
        5,
        64,
        True,
    )
    assert success
    assert bitwork_str == "0a2f.15"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("0a2f848888888888888888888888888888888888888888888888888888888888"),
        "0a2f",
        3,
        1,
        5,
        64,
        False,
    )
    assert not success

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("0a2f048888888888888888888888888888888888888888888888888888888888"),
        "0a2f",
        3,
        1,
        5,
        64,
        True,
    )
    assert success
    assert bitwork_str == "0a2f0"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("0a2f058888888888888888888888888888888888888888888888888888888888"),
        "0a2f",
        3,
        1,
        5,
        64,
        True,
    )
    assert success
    assert bitwork_str == "0a2f0"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("0a2f388888888888888888888888888888888888888888888888888888888888"),
        "0a2f",
        3,
        1,
        5,
        64,
        True,
    )
    assert not success

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("0a2f838888888888888888888888888888888888888888888888888888888888"),
        "0a2f",
        3,
        1,
        5,
        64,
        True,
    )
    assert not success


def test_calculate_expected_bitwork_rollover4():
    assert calculate_expected_bitwork("33333", 3, 1, 2, 64) == "3333.6"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("3333000000000000000000000000000000000000000000000000000000000000"),
        "33333",
        3,
        1,
        2,
        64,
        False,
    )
    assert not success

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("3333600000000000000000000000000000000000000000000000000000000000"),
        "33333",
        3,
        1,
        2,
        64,
        False,
    )
    assert success
    assert bitwork_str == "3333.6"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("3333700000000000000000000000000000000000000000000000000000000000"),
        "33333",
        3,
        1,
        2,
        64,
        False,
    )
    assert success
    assert bitwork_str == "3333.6"

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("3333300000000000000000000000000000000000000000000000000000000000"),
        "33333",
        3,
        1,
        2,
        64,
        False,
    )
    assert not success

    success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
        hex_str_to_hash("3333300000000000000000000000000000000000000000000000000000000000"),
        "33333",
        3,
        1,
        2,
        64,
        True,
    )
    assert success
    assert bitwork_str == "33333"


def test_calculate_expected_bitwork_rollover5():
    testvec = [
        {
            "txid": "3333000000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 0,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "3333",
        },
        {
            "txid": "3333000000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 1,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": False,
            "bitwork_match": None,
        },
        {
            "txid": "3333100000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 1,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "3333.1",
        },
        {
            "txid": "3333100000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 2,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": False,
            "bitwork_match": None,
        },
        {
            "txid": "3333200000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 2,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "3333.2",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 2,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "3333.2",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 2,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": False,
            "expect": True,
            "bitwork_match": "3333.2",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 3,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": False,
            "expect": True,
            "bitwork_match": "3333.3",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 4,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": False,
            "expect": False,
            "bitwork_match": None,
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 4,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "33333",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 5,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "33333",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 6,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "33333",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 7,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "33333",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 8,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "33333",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 9,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "33333",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 10,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "33333",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 11,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "33333",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 12,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "33333",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 13,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "33333",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 14,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "33333",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 15,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "33333",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 16,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "33333",
        },
        {
            "txid": "3333300000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 17,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": False,
            "bitwork_match": None,
        },
        {
            "txid": "3333310000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 17,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "33333.1",
        },
        {
            "txid": "3333340000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 20,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": False,
            "expect": True,
            "bitwork_match": "33333.4",
        },
        {
            "txid": "3333330000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 20,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": False,
            "expect": False,
            "bitwork_match": None,
        },
        {
            "txid": "3333330000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 20,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": True,
            "bitwork_match": "333333",
        },
        {
            "txid": "3333320000000000000000000000000000000000000000000000000000000000",
            "bitworkvec": "333333",
            "mints": 20,
            "max_mints": 1,
            "inc": 1,
            "start": 64,
            "allow_higher": True,
            "expect": False,
            "bitwork_match": None,
        },
    ]

    for x in testvec:
        success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
            hex_str_to_hash(x["txid"]),
            x["bitworkvec"],
            x["mints"],
            x["max_mints"],
            x["inc"],
            x["start"],
            x["allow_higher"],
        )
        if success != x["expect"]:
            print(f"failure: success={success} x={x}")

        assert success == x["expect"]

        if x["expect"]:
            if bitwork_str != x["bitwork_match"]:
                print(f"failure: success={success} x={x}")
            assert bitwork_str == x["bitwork_match"]


def test_get_next_bitwork_full_str():
    assert get_next_bitwork_full_str("", 0) == "0"
    assert get_next_bitwork_full_str("", 1) == "00"
    assert get_next_bitwork_full_str("", 2) == "000"

    assert get_next_bitwork_full_str("8", 0) == "8"
    assert get_next_bitwork_full_str("8", 1) == "80"

    assert get_next_bitwork_full_str("88", 0) == "8"
    assert get_next_bitwork_full_str("88", 1) == "88"
    assert get_next_bitwork_full_str("88", 2) == "880"

    assert get_next_bitwork_full_str("888", 0) == "8"
    assert get_next_bitwork_full_str("888", 1) == "88"
    assert get_next_bitwork_full_str("888", 2) == "888"
    assert get_next_bitwork_full_str("888", 3) == "8880"

    assert get_next_bitwork_full_str("8888", 0) == "8"
    assert get_next_bitwork_full_str("8888", 1) == "88"
    assert get_next_bitwork_full_str("8888", 2) == "888"
    assert get_next_bitwork_full_str("8888", 3) == "8888"

    assert get_next_bitwork_full_str("88888", 0) == "8"
    assert get_next_bitwork_full_str("88888", 1) == "88"
    assert get_next_bitwork_full_str("88888", 2) == "888"
    assert get_next_bitwork_full_str("88888", 3) == "8888"
    assert get_next_bitwork_full_str("88888", 4) == "88888"
