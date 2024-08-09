import pytest

from electrumx.lib.atomicals_blueprint_builder import AtomicalsTransferBlueprintBuilder
from electrumx.lib.coins import Bitcoin
from electrumx.lib.psbt import parse_psbt_hex_and_operations
from electrumx.lib.util_atomicals import (
    location_id_bytes_to_compact,
    parse_atomicals_operations_from_tap_leafs,
    parse_protocols_operations_from_witness_array,
)

coin = Bitcoin


class MockLogger:
    def debug(self, msg):
        return

    def info(self, msg):
        return

    def warning(self, msg):
        return


def test_empty_spends():
    tx_hash = b""
    raw_tx_str = "0100000001d28e50125bdab2715392117ce8af4419fd3480649938002d53c926e22412e02d000000006b483045022100ee9a84d224d0c41b0eb9c62a4bb5aff52a2760ae19dbae9b55e818b567d6b17002204c7a0e5337b3181dc0824c8dd2024cd4ae784183044958baac282aa8fd77a45a012102c8d7a451322a30a7d6a9e3c5b187110f38cb13b16ef15f01e6e2d5282c4e6c97ffffffff01d8afa90000000000160014cef15c6f75fcd66076c5b69386a41849abd1195400000000"
    raw_tx = bytes.fromhex(raw_tx_str)
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()

    def mock_mint_fetcher(self, atomical_id):
        return None

    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(), {}, {}, tx_hash, tx, mock_mint_fetcher, True, False
    )
    assert blueprint_builder

    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0

    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 0
    assert ft_output_blueprint.first_atomical_id is None
    assert blueprint_builder.are_fts_burned == False

    # Log that there were tokens burned due to not being cleanly assigned
    assert blueprint_builder.get_are_fts_burned() == False


def test_spends_ft_burned():
    raw_tx_str = "0100000000010194578be9bc16dfdef6f58ef5bd2aa4828718c6602da20a363588e70db12318160000000000ffffffff01e8030000000000002251206068a57a273b499e7bdaae062cd4b15dc4ddb602182ce0ebbfa04f143d2796880340dae087925e4e7dd1ed3217f945e1fa799975e4f825ad35b7376625c7e58b7c066e2d30b1b8837e73dce3f892748ef9debbab4a66472b36c9780d688043bc93286a2037fc7282c932b06d79257eae409224f5fb1fa283a7eb7d90d1e8e6e2dec78954ac00630461746f6d03646d743ba16461726773a468626974776f726b6364313631386b6d696e745f7469636b65726461746f6d656e6f6e63651a003cdbbb6474696d651a650a94566821c137fc7282c932b06d79257eae409224f5fb1fa283a7eb7d90d1e8e6e2dec7895400000000"
    raw_tx = bytes.fromhex(raw_tx_str)

    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x00"
    )
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    atomicals_spent_at_inputs = {
        0: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"\xb2\x90h\x91\xf2y\xf9\xc1\xdc2\x12\xf4\x8f,S\xb5x\xb7y!\x89\xa3\xbb\xff\xcd\xe4(\xc4\xa1\xd3}\\\x00\x00\x00\x00",
                "data": b"t&\xd4\xd8\xbd\x9a?:\x8b\x9bj\xc2\x93L\\\xd5\xedU\xdd\x01\x03\xf1q\xe2 \xaf#6\xe3\x9a\xc3\r[\xbeTS\xda\xc1\xd39\x05\xa2\xcf\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00\x9f\x87\x7f5\x00",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        1: [
            {
                "atomical_id": b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x00",
                "location_id": b"\xbe\\\x19\xb0\x92\xce\xc2]c\xdf\xc7\xb8\x90,Qj\x88\x19`m\x7f\xcc\x01&VAbI@\xf2\x10|\x00\x00\x00\x00",
                "data": b"t&\xd4\xd8\xbd\x9a?:\x8b\x9bj\xc2\x93L\\\xd5\xedU\xdd\x01\x03\xf1q\xe2 \xaf#6\xe3\x9a\xc3\r[\xbeTS\xda\xc1\xd39\x05\xa2\xcf\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00\xa2\x87\x7f5\x00",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        2: [
            {
                "atomical_id": b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x00",
                "location_id": b"\\\xbe\x08\xaf\xba\xe6\x87+\x9cL\x9c\x8e%|\xbdY/\xf2\x1e4\xbb\xd1\x7f~3\x91\xb2\xa9z7W\xcd\x00\x00\x00\x00",
                "data": b"t&\xd4\xd8\xbd\x9a?:\x8b\x9bj\xc2\x93L\\\xd5\xedU\xdd\x01\x03\xf1q\xe2 \xaf#6\xe3\x9a\xc3\r[\xbeTS\xda\xc1\xd39\x05\xa2\xcf\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00\xfd\x8e\x7f5\x00",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        3: [
            {
                "atomical_id": b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x00",
                "location_id": b"\xa3\x9b\xfe\xc9e\xef\x90\x816\x1c\x85&|\xe6\xab\x16\xe7\x1e{\x1b\xee8l\xddp&\x13+\xd9\xe5\xad\x0f\x00\x00\x00\x00",
                "data": b"t&\xd4\xd8\xbd\x9a?:\x8b\x9bj\xc2\x93L\\\xd5\xedU\xdd\x01\x03\xf1q\xe2 \xaf#6\xe3\x9a\xc3\r[\xbeTS\xda\xc1\xd39\x05\xa2\xcf\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8f\x7f5\x00",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        4: [
            {
                "atomical_id": b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x00",
                "location_id": b'\xccc\xfb\x9d\xbe\xc2+\x07Gb}\xb0\x08#\xc1S\xd9q\x1c\x86P\xfa\xfe\xce!\x93"$\xf8\xd4d\xd5\x00\x00\x00\x00',
                "data": b"t&\xd4\xd8\xbd\x9a?:\x8b\x9bj\xc2\x93L\\\xd5\xedU\xdd\x01\x03\xf1q\xe2 \xaf#6\xe3\x9a\xc3\r[\xbeTS\xda\xc1\xd39\x05\xa2\xcf\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00\x03\x8f\x7f5\x00",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        5: [
            {
                "atomical_id": b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x00",
                "location_id": b"\t#,>,`b\xc0<\x8a\xc2\xe9\x87OyK\x9cY\xac^\x13\xa3\x97\t\xaezA\xcb5 \x1b\x96\x00\x00\x00\x00",
                "data": b"t&\xd4\xd8\xbd\x9a?:\x8b\x9bj\xc2\x93L\\\xd5\xedU\xdd\x01\x03\xf1q\xe2 \xaf#6\xe3\x9a\xc3\r[\xbeTS\xda\xc1\xd39\x05\xa2\xcf\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00\xb2\xa6\x7f5\x00",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        6: [
            {
                "atomical_id": b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x00",
                "location_id": b"\x0c\xa0\xe7\xc8\xef\n\xaa\xc3\x10\x83$4\xdd\xa5 \xa6\x7fo\x0e\xe6$\xe3\x8d?\xf0\x13+\x1b\x1b\x029\x8c\x00\x00\x00\x00",
                "data": b"t&\xd4\xd8\xbd\x9a?:\x8b\x9bj\xc2\x93L\\\xd5\xedU\xdd\x01\x03\xf1q\xe2 \xaf#6\xe3\x9a\xc3\r[\xbeTS\xda\xc1\xd39\x05\xa2\xcf\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00\xe4\xaa\x7f5\x00",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        7: [
            {
                "atomical_id": b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x00",
                "location_id": b'|\xcf:\xbf\x84\x16\x1d\xdbl\xd2"C\xef\x1b\x16\xf8\xdd\xf4\xae\x9bY\xf3\xe8\xc7\xae1N^W\x1dy\xba\x00\x00\x00\x00',
                "data": b"t&\xd4\xd8\xbd\x9a?:\x8b\x9bj\xc2\x93L\\\xd5\xedU\xdd\x01\x03\xf1q\xe2 \xaf#6\xe3\x9a\xc3\r[\xbeTS\xda\xc1\xd39\x05\xa2\xcf\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00\x16\xfb\x7f5\x00",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        8: [
            {
                "atomical_id": b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x00",
                "location_id": b"\t\xe1\xd9\xd2\x8c\x06\xd4\x87\xc8+5\x1d\x88\xe4\xbd\xb92\xa6=I\x89\xd3\xaa\xbe`;\xba\x04\xe5\xc6F\xc0\x00\x00\x00\x00",
                "data": b"t&\xd4\xd8\xbd\x9a?:\x8b\x9bj\xc2\x93L\\\xd5\xedU\xdd\x01\x03\xf1q\xe2 \xaf#6\xe3\x9a\xc3\r[\xbeTS\xda\xc1\xd39\x05\xa2\xcf\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00\x1d\xfb\x7f5\x00",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        9: [
            {
                "atomical_id": b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x00",
                "location_id": b"T\x99\x02\x16\xd2\xbag\x97\xc6\xd5UwO\x02\xde]\xe7\xd2w\xfe\xfd0e\x88\xb0\x92\xec\x14\\VDu\x00\x00\x00\x00",
                "data": b"t&\xd4\xd8\xbd\x9a?:\x8b\x9bj\xc2\x93L\\\xd5\xedU\xdd\x01\x03\xf1q\xe2 \xaf#6\xe3\x9a\xc3\r[\xbeTS\xda\xc1\xd39\x05\xa2\xcf\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00!\xfb\x7f5\x00",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        10: [
            {
                "atomical_id": b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x00",
                "location_id": b"Z\xcaR\xee\xba\x8a\x03+\xd0\xa3n\xf2\xae#\xf3\xc7\x94\x8a\x12\xe4$\xdf\x0fE\x0b\n\xa2\xfa\x0c\xb1\xb1c\x00\x00\x00\x00",
                "data": b"t&\xd4\xd8\xbd\x9a?:\x8b\x9bj\xc2\x93L\\\xd5\xedU\xdd\x01\x03\xf1q\xe2 \xaf#6\xe3\x9a\xc3\r[\xbeTS\xda\xc1\xd39\x05\xa2\xcf\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00L\t\x805\x00",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
    }

    def mock_mint_fetcher(self, atomical_id):
        return {"atomical_id": atomical_id, "type": "FT"}

    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        {},
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        False,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0

    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 1
    assert ft_output_blueprint.first_atomical_id == subject_atomical_id
    assert len(ft_output_blueprint.fts_burned) == 1
    assert ft_output_blueprint.fts_burned[subject_atomical_id] == 10000

    # Log that there were tokens burned due to not being cleanly assigned
    assert blueprint_builder.get_are_fts_burned() == True


def test_spends_ft_valid():
    raw_tx_str = "0200000000010cb2906891f279f9c1dc3212f48f2c53b578b7792189a3bbffcde428c4a1d37d5c0000000000ffffffffbe5c19b092cec25d63dfc7b8902c516a8819606d7fcc01265641624940f2107c0000000000ffffffff5cbe08afbae6872b9c4c9c8e257cbd592ff21e34bbd17f7e3391b2a97a3757cd0000000000ffffffffa39bfec965ef9081361c85267ce6ab16e71e7b1bee386cdd7026132bd9e5ad0f0000000000ffffffffcc63fb9dbec22b0747627db00823c153d9711c8650fafece21932224f8d464d50000000000ffffffff09232c3e2c6062c03c8ac2e9874f794b9c59ac5e13a39709ae7a41cb35201b960000000000ffffffff0ca0e7c8ef0aaac310832434dda520a67f6f0ee624e38d3ff0132b1b1b02398c0000000000ffffffff7ccf3abf84161ddb6cd22243ef1b16f8ddf4ae9b59f3e8c7ae314e5e571d79ba0000000000ffffffff09e1d9d28c06d487c82b351d88e4bdb932a63d4989d3aabe603bba04e5c646c00000000000ffffffff54990216d2ba6797c6d555774f02de5de7d277fefd306588b092ec145c5644750000000000ffffffff5aca52eeba8a032bd0a36ef2ae23f3c7948a12e424df0f450b0aa2fa0cb1b1630000000000ffffffff45cee1dc386b8996c084ed0ebf251c012d9e3c531f29c5c81856b947f1b61a4a0000000000ffffffff01f82a00000000000022512032180020ce893cf7a5b3b29f010dfb88af61ffc975f462d1d01c196463aa54240140d7f79372cb379f1f3362d70d0b6b9eaa25c2d671e337d5b613bba07c9568c55733fa8e117153e614ccb2f06ff6192452dee57855679a7100d64b3d58b894cc6d01404932d53958e4449d4ebd1680713405f6b8ce5bcc9fcb2e51a7142e1ff299bac530b19097c597e12854ae5f2baeab17679de622e44745a12b5d9fe173fb8483bb0140684cc8ce62b2b11d58b374fba82c6c9d0a74fd21bda8255e60fcf1a37c99c182bce23405709a173fdc7647c8da70deb1097724a11547b830896825b3f35f49630140d7c76f8a78c43d5e63f64566a18c1a97cb045d9bc4d515c5f50e9a04b3b98848d08e7539a9cc5a33592de05112ae5079f7051cad315faa3805b41e15ab553bd00140c2977fe811c8a853d422288194043ee70616d7ba64d184f2bb70427622e8d5a3cd46042dc73ef2c546be23e3ecf5df9ba102462ca5e98c73e8bc10699c40b7490140a3fe2d0bd549e56b9b8a6bed011cdf905e191234d23facf9cbce9fca698ece58c9904d2a41f4b2ddd19a498ef327661596e16aa5a48c967e3ecbc8f38600f3280140bce200f9d28e1751c8b4c85366062637d1297a22e4b65d4bc78702a7ccb1cba668bbf7415cf436928f353a34dd16949da78d498708ff6ca581fd7eed1cb8df7b0140419eba31f213b531b7981cb317f24eb9ee952384807304a52841b318b0b65ec655d7dbf009e750d2c4a214d23614b57c3cc71f03be90de90482c307d99f8e4d5014050bf388db2ccbb2c1d0ae7c043be5fc8996050abf6d3727531af124d2c6e11855de0333b0e7bd62911fdda0e481dc9cd20790286856bd5932c969901ef21381f0140325a460a4e241e78a24fe2a830363710a11e26c53307611eb90b6ea19db5472680f2ed04b13b5582b730cd96524e9ff89fa16e0942b841f61c4454a06e36c3b3014057901a51a226de41d6e7e6df666ada1ce0f14ec5c535418d10fbc8461d988cdbf70f0b8e8441743a6a39c184aa9ee95cfe11f7ae8c75720a678d4184aa7a7d1c01403fe06d7121381d81589a74a7927d75769eb70132585df7309f817d30c69be79d74a7a383ad7dab079436276f7388cdddbfd80add939b6a6cc3d194f0d6d2ccd800000000"
    raw_tx = bytes.fromhex(raw_tx_str)

    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x00"
    )

    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    atomicals_spent_at_inputs = {
        0: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        1: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        2: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        3: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        4: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        5: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        6: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        7: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        8: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        9: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        10: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
    }

    def mock_mint_fetcher(self, atomical_id):
        return {"atomical_id": atomical_id, "type": "FT"}

    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        {},
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        False,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0

    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 1
    assert ft_output_blueprint.first_atomical_id == subject_atomical_id
    assert len(ft_output_blueprint.fts_burned) == 0
    assert blueprint_builder.get_are_fts_burned() == False


def test_spends_ft_multiple_valid_collapsed():
    raw_tx_str = "0200000000010cb2906891f279f9c1dc3212f48f2c53b578b7792189a3bbffcde428c4a1d37d5c0000000000ffffffffbe5c19b092cec25d63dfc7b8902c516a8819606d7fcc01265641624940f2107c0000000000ffffffff5cbe08afbae6872b9c4c9c8e257cbd592ff21e34bbd17f7e3391b2a97a3757cd0000000000ffffffffa39bfec965ef9081361c85267ce6ab16e71e7b1bee386cdd7026132bd9e5ad0f0000000000ffffffffcc63fb9dbec22b0747627db00823c153d9711c8650fafece21932224f8d464d50000000000ffffffff09232c3e2c6062c03c8ac2e9874f794b9c59ac5e13a39709ae7a41cb35201b960000000000ffffffff0ca0e7c8ef0aaac310832434dda520a67f6f0ee624e38d3ff0132b1b1b02398c0000000000ffffffff7ccf3abf84161ddb6cd22243ef1b16f8ddf4ae9b59f3e8c7ae314e5e571d79ba0000000000ffffffff09e1d9d28c06d487c82b351d88e4bdb932a63d4989d3aabe603bba04e5c646c00000000000ffffffff54990216d2ba6797c6d555774f02de5de7d277fefd306588b092ec145c5644750000000000ffffffff5aca52eeba8a032bd0a36ef2ae23f3c7948a12e424df0f450b0aa2fa0cb1b1630000000000ffffffff45cee1dc386b8996c084ed0ebf251c012d9e3c531f29c5c81856b947f1b61a4a0000000000ffffffff01f82a00000000000022512032180020ce893cf7a5b3b29f010dfb88af61ffc975f462d1d01c196463aa54240140d7f79372cb379f1f3362d70d0b6b9eaa25c2d671e337d5b613bba07c9568c55733fa8e117153e614ccb2f06ff6192452dee57855679a7100d64b3d58b894cc6d01404932d53958e4449d4ebd1680713405f6b8ce5bcc9fcb2e51a7142e1ff299bac530b19097c597e12854ae5f2baeab17679de622e44745a12b5d9fe173fb8483bb0140684cc8ce62b2b11d58b374fba82c6c9d0a74fd21bda8255e60fcf1a37c99c182bce23405709a173fdc7647c8da70deb1097724a11547b830896825b3f35f49630140d7c76f8a78c43d5e63f64566a18c1a97cb045d9bc4d515c5f50e9a04b3b98848d08e7539a9cc5a33592de05112ae5079f7051cad315faa3805b41e15ab553bd00140c2977fe811c8a853d422288194043ee70616d7ba64d184f2bb70427622e8d5a3cd46042dc73ef2c546be23e3ecf5df9ba102462ca5e98c73e8bc10699c40b7490140a3fe2d0bd549e56b9b8a6bed011cdf905e191234d23facf9cbce9fca698ece58c9904d2a41f4b2ddd19a498ef327661596e16aa5a48c967e3ecbc8f38600f3280140bce200f9d28e1751c8b4c85366062637d1297a22e4b65d4bc78702a7ccb1cba668bbf7415cf436928f353a34dd16949da78d498708ff6ca581fd7eed1cb8df7b0140419eba31f213b531b7981cb317f24eb9ee952384807304a52841b318b0b65ec655d7dbf009e750d2c4a214d23614b57c3cc71f03be90de90482c307d99f8e4d5014050bf388db2ccbb2c1d0ae7c043be5fc8996050abf6d3727531af124d2c6e11855de0333b0e7bd62911fdda0e481dc9cd20790286856bd5932c969901ef21381f0140325a460a4e241e78a24fe2a830363710a11e26c53307611eb90b6ea19db5472680f2ed04b13b5582b730cd96524e9ff89fa16e0942b841f61c4454a06e36c3b3014057901a51a226de41d6e7e6df666ada1ce0f14ec5c535418d10fbc8461d988cdbf70f0b8e8441743a6a39c184aa9ee95cfe11f7ae8c75720a678d4184aa7a7d1c01403fe06d7121381d81589a74a7927d75769eb70132585df7309f817d30c69be79d74a7a383ad7dab079436276f7388cdddbfd80add939b6a6cc3d194f0d6d2ccd800000000"
    raw_tx = bytes.fromhex(raw_tx_str)

    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x01"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x00"
    )

    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    atomicals_spent_at_inputs = {
        0: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ],
        1: [
            {
                "atomical_id": subject_atomical_id2,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 3000, "atomical_value": 3000},
            }
        ],
        2: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
        3: [
            {
                "atomical_id": subject_atomical_id2,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
        4: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
        5: [
            {
                "atomical_id": subject_atomical_id2,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
        6: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
        7: [
            {
                "atomical_id": subject_atomical_id2,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
        8: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
        9: [
            {
                "atomical_id": subject_atomical_id2,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
        10: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
    }

    def mock_mint_fetcher(self, atomical_id):
        return {"atomical_id": atomical_id, "type": "FT"}

    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        {},
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        False,
    )

    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 1
    assert ft_output_blueprint.first_atomical_id == subject_atomical_id
    assert len(ft_output_blueprint.fts_burned) == 0
    assert ft_output_blueprint.cleanly_assigned == False
    assert blueprint_builder.get_are_fts_burned() == False


def test_spends_ft_single_burned_under():
    raw_tx_str = "0200000000010cb2906891f279f9c1dc3212f48f2c53b578b7792189a3bbffcde428c4a1d37d5c0000000000ffffffffbe5c19b092cec25d63dfc7b8902c516a8819606d7fcc01265641624940f2107c0000000000ffffffff5cbe08afbae6872b9c4c9c8e257cbd592ff21e34bbd17f7e3391b2a97a3757cd0000000000ffffffffa39bfec965ef9081361c85267ce6ab16e71e7b1bee386cdd7026132bd9e5ad0f0000000000ffffffffcc63fb9dbec22b0747627db00823c153d9711c8650fafece21932224f8d464d50000000000ffffffff09232c3e2c6062c03c8ac2e9874f794b9c59ac5e13a39709ae7a41cb35201b960000000000ffffffff0ca0e7c8ef0aaac310832434dda520a67f6f0ee624e38d3ff0132b1b1b02398c0000000000ffffffff7ccf3abf84161ddb6cd22243ef1b16f8ddf4ae9b59f3e8c7ae314e5e571d79ba0000000000ffffffff09e1d9d28c06d487c82b351d88e4bdb932a63d4989d3aabe603bba04e5c646c00000000000ffffffff54990216d2ba6797c6d555774f02de5de7d277fefd306588b092ec145c5644750000000000ffffffff5aca52eeba8a032bd0a36ef2ae23f3c7948a12e424df0f450b0aa2fa0cb1b1630000000000ffffffff45cee1dc386b8996c084ed0ebf251c012d9e3c531f29c5c81856b947f1b61a4a0000000000ffffffff01f82a00000000000022512032180020ce893cf7a5b3b29f010dfb88af61ffc975f462d1d01c196463aa54240140d7f79372cb379f1f3362d70d0b6b9eaa25c2d671e337d5b613bba07c9568c55733fa8e117153e614ccb2f06ff6192452dee57855679a7100d64b3d58b894cc6d01404932d53958e4449d4ebd1680713405f6b8ce5bcc9fcb2e51a7142e1ff299bac530b19097c597e12854ae5f2baeab17679de622e44745a12b5d9fe173fb8483bb0140684cc8ce62b2b11d58b374fba82c6c9d0a74fd21bda8255e60fcf1a37c99c182bce23405709a173fdc7647c8da70deb1097724a11547b830896825b3f35f49630140d7c76f8a78c43d5e63f64566a18c1a97cb045d9bc4d515c5f50e9a04b3b98848d08e7539a9cc5a33592de05112ae5079f7051cad315faa3805b41e15ab553bd00140c2977fe811c8a853d422288194043ee70616d7ba64d184f2bb70427622e8d5a3cd46042dc73ef2c546be23e3ecf5df9ba102462ca5e98c73e8bc10699c40b7490140a3fe2d0bd549e56b9b8a6bed011cdf905e191234d23facf9cbce9fca698ece58c9904d2a41f4b2ddd19a498ef327661596e16aa5a48c967e3ecbc8f38600f3280140bce200f9d28e1751c8b4c85366062637d1297a22e4b65d4bc78702a7ccb1cba668bbf7415cf436928f353a34dd16949da78d498708ff6ca581fd7eed1cb8df7b0140419eba31f213b531b7981cb317f24eb9ee952384807304a52841b318b0b65ec655d7dbf009e750d2c4a214d23614b57c3cc71f03be90de90482c307d99f8e4d5014050bf388db2ccbb2c1d0ae7c043be5fc8996050abf6d3727531af124d2c6e11855de0333b0e7bd62911fdda0e481dc9cd20790286856bd5932c969901ef21381f0140325a460a4e241e78a24fe2a830363710a11e26c53307611eb90b6ea19db5472680f2ed04b13b5582b730cd96524e9ff89fa16e0942b841f61c4454a06e36c3b3014057901a51a226de41d6e7e6df666ada1ce0f14ec5c535418d10fbc8461d988cdbf70f0b8e8441743a6a39c184aa9ee95cfe11f7ae8c75720a678d4184aa7a7d1c01403fe06d7121381d81589a74a7927d75769eb70132585df7309f817d30c69be79d74a7a383ad7dab079436276f7388cdddbfd80add939b6a6cc3d194f0d6d2ccd800000000"
    raw_tx = bytes.fromhex(raw_tx_str)
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x01"
    )
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    atomicals_spent_at_inputs = {
        0: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 10999, "atomical_value": 10999},
            }
        ]
    }

    def mock_mint_fetcher(self, atomical_id):
        return {"atomical_id": atomical_id, "type": "FT"}

    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        {},
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        False,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0

    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 0
    assert ft_output_blueprint.fts_burned[subject_atomical_id] == 10999
    assert ft_output_blueprint.first_atomical_id == subject_atomical_id
    assert blueprint_builder.get_are_fts_burned() == True


def test_spends_ft_single_burned_over():
    raw_tx_str = "0200000000010cb2906891f279f9c1dc3212f48f2c53b578b7792189a3bbffcde428c4a1d37d5c0000000000ffffffffbe5c19b092cec25d63dfc7b8902c516a8819606d7fcc01265641624940f2107c0000000000ffffffff5cbe08afbae6872b9c4c9c8e257cbd592ff21e34bbd17f7e3391b2a97a3757cd0000000000ffffffffa39bfec965ef9081361c85267ce6ab16e71e7b1bee386cdd7026132bd9e5ad0f0000000000ffffffffcc63fb9dbec22b0747627db00823c153d9711c8650fafece21932224f8d464d50000000000ffffffff09232c3e2c6062c03c8ac2e9874f794b9c59ac5e13a39709ae7a41cb35201b960000000000ffffffff0ca0e7c8ef0aaac310832434dda520a67f6f0ee624e38d3ff0132b1b1b02398c0000000000ffffffff7ccf3abf84161ddb6cd22243ef1b16f8ddf4ae9b59f3e8c7ae314e5e571d79ba0000000000ffffffff09e1d9d28c06d487c82b351d88e4bdb932a63d4989d3aabe603bba04e5c646c00000000000ffffffff54990216d2ba6797c6d555774f02de5de7d277fefd306588b092ec145c5644750000000000ffffffff5aca52eeba8a032bd0a36ef2ae23f3c7948a12e424df0f450b0aa2fa0cb1b1630000000000ffffffff45cee1dc386b8996c084ed0ebf251c012d9e3c531f29c5c81856b947f1b61a4a0000000000ffffffff01f82a00000000000022512032180020ce893cf7a5b3b29f010dfb88af61ffc975f462d1d01c196463aa54240140d7f79372cb379f1f3362d70d0b6b9eaa25c2d671e337d5b613bba07c9568c55733fa8e117153e614ccb2f06ff6192452dee57855679a7100d64b3d58b894cc6d01404932d53958e4449d4ebd1680713405f6b8ce5bcc9fcb2e51a7142e1ff299bac530b19097c597e12854ae5f2baeab17679de622e44745a12b5d9fe173fb8483bb0140684cc8ce62b2b11d58b374fba82c6c9d0a74fd21bda8255e60fcf1a37c99c182bce23405709a173fdc7647c8da70deb1097724a11547b830896825b3f35f49630140d7c76f8a78c43d5e63f64566a18c1a97cb045d9bc4d515c5f50e9a04b3b98848d08e7539a9cc5a33592de05112ae5079f7051cad315faa3805b41e15ab553bd00140c2977fe811c8a853d422288194043ee70616d7ba64d184f2bb70427622e8d5a3cd46042dc73ef2c546be23e3ecf5df9ba102462ca5e98c73e8bc10699c40b7490140a3fe2d0bd549e56b9b8a6bed011cdf905e191234d23facf9cbce9fca698ece58c9904d2a41f4b2ddd19a498ef327661596e16aa5a48c967e3ecbc8f38600f3280140bce200f9d28e1751c8b4c85366062637d1297a22e4b65d4bc78702a7ccb1cba668bbf7415cf436928f353a34dd16949da78d498708ff6ca581fd7eed1cb8df7b0140419eba31f213b531b7981cb317f24eb9ee952384807304a52841b318b0b65ec655d7dbf009e750d2c4a214d23614b57c3cc71f03be90de90482c307d99f8e4d5014050bf388db2ccbb2c1d0ae7c043be5fc8996050abf6d3727531af124d2c6e11855de0333b0e7bd62911fdda0e481dc9cd20790286856bd5932c969901ef21381f0140325a460a4e241e78a24fe2a830363710a11e26c53307611eb90b6ea19db5472680f2ed04b13b5582b730cd96524e9ff89fa16e0942b841f61c4454a06e36c3b3014057901a51a226de41d6e7e6df666ada1ce0f14ec5c535418d10fbc8461d988cdbf70f0b8e8441743a6a39c184aa9ee95cfe11f7ae8c75720a678d4184aa7a7d1c01403fe06d7121381d81589a74a7927d75769eb70132585df7309f817d30c69be79d74a7a383ad7dab079436276f7388cdddbfd80add939b6a6cc3d194f0d6d2ccd800000000"
    raw_tx = bytes.fromhex(raw_tx_str)
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x01"
    )
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    atomicals_spent_at_inputs = {
        0: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 11001, "atomical_value": 11001},
            }
        ]
    }

    def mock_mint_fetcher(self, atomical_id):
        return {"atomical_id": atomical_id, "type": "FT"}

    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        {},
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        False,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 1
    assert ft_output_blueprint.fts_burned[subject_atomical_id] == 1
    assert ft_output_blueprint.first_atomical_id == subject_atomical_id
    assert blueprint_builder.get_are_fts_burned() == True


def test_spends_are_payments_satisfied_checks():
    raw_tx_str = "02000000000101647760b13086a2f2e77395e474305237afa65ec638dda01132c8c48c8b891fd00000000000ffffffff03a8610000000000002251208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749679a861000000000000225120ed2ec645d1749c9b2dba88b1346899c60c82f7a57e6359964393a2bba31450f200000000000000002d6a0461746f6d017024921bd27146f57d42565b373214ae7f6d05fa85c3f73eeb5dd876c4c81be58888000000000140d94db131ec889cb33fc258bc3bb5ace3656597cde88cf51494ae864f171915d262a50af24e3699560116450c4244a99b7d84602b8be1fe4c640250d2202330c800000000"
    raw_tx = bytes.fromhex(raw_tx_str)
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    atomicals_spent_at_inputs = {}

    def mock_mint_fetcher(self, atomical_id):
        return {"atomical_id": atomical_id, "type": "FT"}

    operations_at_inputs = {}
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operations_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        False,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert ft_output_blueprint.cleanly_assigned == True
    assert blueprint_builder.get_are_fts_burned() == False

    # Empty rules
    rules = {}
    payment_valid = blueprint_builder.are_payments_satisfied(rules)
    assert not payment_valid
    # Valid payment to 2 outputs
    rules = {
        "51208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749679": {"v": 25000},
        "5120ed2ec645d1749c9b2dba88b1346899c60c82f7a57e6359964393a2bba31450f2": {"v": 25000},
    }
    payment_valid = blueprint_builder.are_payments_satisfied(rules)
    assert payment_valid
    # Valid payment to one output
    rules = {"51208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749679": {"v": 25000}}
    payment_valid = blueprint_builder.are_payments_satisfied(rules)
    assert payment_valid
    # Invalid payment insufficient amount
    rules = {"51208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749679": {"v": 25001}}
    payment_valid = blueprint_builder.are_payments_satisfied(rules)
    assert not payment_valid
    # Valid payment higher amount
    rules = {"51208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749679": {"v": 24999}}
    payment_valid = blueprint_builder.are_payments_satisfied(rules)
    assert payment_valid
    # Invalid payment to wrong address
    rules = {"51208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749678": {"v": 25000}}
    payment_valid = blueprint_builder.are_payments_satisfied(rules)
    assert not payment_valid


def test_spends_fts_are_payments_satisfied_checks2():
    raw_tx_str = "02000000000101647760b13086a2f2e77395e474305237afa65ec638dda01132c8c48c8b891fd00000000000ffffffff03a8610000000000002251208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749679a861000000000000225120ed2ec645d1749c9b2dba88b1346899c60c82f7a57e6359964393a2bba31450f200000000000000002d6a0461746f6d017024921bd27146f57d42565b373214ae7f6d05fa85c3f73eeb5dd876c4c81be58888000000000140d94db131ec889cb33fc258bc3bb5ace3656597cde88cf51494ae864f171915d262a50af24e3699560116450c4244a99b7d84602b8be1fe4c640250d2202330c800000000"
    raw_tx = bytes.fromhex(raw_tx_str)
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    atomicals_spent_at_inputs = {
        0: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 50000, "atomical_value": 50000},
            }
        ]
    }

    def mock_mint_fetcher(self, atomical_id):
        return {"atomical_id": atomical_id, "type": "FT"}

    operations_at_inputs = {}
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operations_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        False,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert ft_output_blueprint.cleanly_assigned == True
    assert blueprint_builder.get_are_fts_burned() == False

    # Invalid due to required payment for specify fungible token
    rules = {
        "51208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749679": {
            "id": "fail",
            "v": 25000,
        }
    }
    payment_valid = blueprint_builder.are_payments_satisfied(rules)
    assert not payment_valid

    # Valid with a valid atomical id ft token
    subject_atomical_id_compact = location_id_bytes_to_compact(subject_atomical_id)
    rules = {
        "51208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749679": {
            "id": subject_atomical_id_compact,
            "v": 25000,
        }
    }
    #
    payment_valid = blueprint_builder.are_payments_satisfied(rules)
    assert payment_valid

    # Invalid due to insufficient units
    subject_atomical_id_compact = location_id_bytes_to_compact(subject_atomical_id)
    rules = {
        "51208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749679": {
            "id": subject_atomical_id_compact,
            "v": 25001,
        }
    }
    payment_valid = blueprint_builder.are_payments_satisfied(rules)
    assert not payment_valid
    # Valid with a valid atomical id ft token higher than needed
    subject_atomical_id_compact = location_id_bytes_to_compact(subject_atomical_id)
    rules = {
        "51208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749679": {
            "id": subject_atomical_id_compact,
            "v": 1,
        }
    }
    #
    payment_valid = blueprint_builder.are_payments_satisfied(rules)
    assert payment_valid

    # Valid with a valid atomical id ft token higher than needed
    subject_atomical_id_compact = location_id_bytes_to_compact(subject_atomical_id)
    rules = {
        "51208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749679": {
            "id": subject_atomical_id_compact,
            "v": 0,
        }
    }
    payment_valid = blueprint_builder.are_payments_satisfied(rules)
    assert payment_valid


# testcase for partially colored split
def test_spends_ft_single_split():
    raw_tx_str = "0200000000010cb2906891f279f9c1dc3212f48f2c53b578b7792189a3bbffcde428c4a1d37d5c0000000000ffffffffbe5c19b092cec25d63dfc7b8902c516a8819606d7fcc01265641624940f2107c0000000000ffffffff5cbe08afbae6872b9c4c9c8e257cbd592ff21e34bbd17f7e3391b2a97a3757cd0000000000ffffffffa39bfec965ef9081361c85267ce6ab16e71e7b1bee386cdd7026132bd9e5ad0f0000000000ffffffffcc63fb9dbec22b0747627db00823c153d9711c8650fafece21932224f8d464d50000000000ffffffff09232c3e2c6062c03c8ac2e9874f794b9c59ac5e13a39709ae7a41cb35201b960000000000ffffffff0ca0e7c8ef0aaac310832434dda520a67f6f0ee624e38d3ff0132b1b1b02398c0000000000ffffffff7ccf3abf84161ddb6cd22243ef1b16f8ddf4ae9b59f3e8c7ae314e5e571d79ba0000000000ffffffff09e1d9d28c06d487c82b351d88e4bdb932a63d4989d3aabe603bba04e5c646c00000000000ffffffff54990216d2ba6797c6d555774f02de5de7d277fefd306588b092ec145c5644750000000000ffffffff5aca52eeba8a032bd0a36ef2ae23f3c7948a12e424df0f450b0aa2fa0cb1b1630000000000ffffffff45cee1dc386b8996c084ed0ebf251c012d9e3c531f29c5c81856b947f1b61a4a0000000000ffffffff01f82a00000000000022512032180020ce893cf7a5b3b29f010dfb88af61ffc975f462d1d01c196463aa54240140d7f79372cb379f1f3362d70d0b6b9eaa25c2d671e337d5b613bba07c9568c55733fa8e117153e614ccb2f06ff6192452dee57855679a7100d64b3d58b894cc6d01404932d53958e4449d4ebd1680713405f6b8ce5bcc9fcb2e51a7142e1ff299bac530b19097c597e12854ae5f2baeab17679de622e44745a12b5d9fe173fb8483bb0140684cc8ce62b2b11d58b374fba82c6c9d0a74fd21bda8255e60fcf1a37c99c182bce23405709a173fdc7647c8da70deb1097724a11547b830896825b3f35f49630140d7c76f8a78c43d5e63f64566a18c1a97cb045d9bc4d515c5f50e9a04b3b98848d08e7539a9cc5a33592de05112ae5079f7051cad315faa3805b41e15ab553bd00140c2977fe811c8a853d422288194043ee70616d7ba64d184f2bb70427622e8d5a3cd46042dc73ef2c546be23e3ecf5df9ba102462ca5e98c73e8bc10699c40b7490140a3fe2d0bd549e56b9b8a6bed011cdf905e191234d23facf9cbce9fca698ece58c9904d2a41f4b2ddd19a498ef327661596e16aa5a48c967e3ecbc8f38600f3280140bce200f9d28e1751c8b4c85366062637d1297a22e4b65d4bc78702a7ccb1cba668bbf7415cf436928f353a34dd16949da78d498708ff6ca581fd7eed1cb8df7b0140419eba31f213b531b7981cb317f24eb9ee952384807304a52841b318b0b65ec655d7dbf009e750d2c4a214d23614b57c3cc71f03be90de90482c307d99f8e4d5014050bf388db2ccbb2c1d0ae7c043be5fc8996050abf6d3727531af124d2c6e11855de0333b0e7bd62911fdda0e481dc9cd20790286856bd5932c969901ef21381f0140325a460a4e241e78a24fe2a830363710a11e26c53307611eb90b6ea19db5472680f2ed04b13b5582b730cd96524e9ff89fa16e0942b841f61c4454a06e36c3b3014057901a51a226de41d6e7e6df666ada1ce0f14ec5c535418d10fbc8461d988cdbf70f0b8e8441743a6a39c184aa9ee95cfe11f7ae8c75720a678d4184aa7a7d1c01403fe06d7121381d81589a74a7927d75769eb70132585df7309f817d30c69be79d74a7a383ad7dab079436276f7388cdddbfd80add939b6a6cc3d194f0d6d2ccd800000000"
    raw_tx = bytes.fromhex(raw_tx_str)
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x01"
    )
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    atomicals_spent_at_inputs = {
        0: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 11001, "atomical_value": 11001},
            }
        ]
    }

    def mock_mint_fetcher(self, atomical_id):
        return {"atomical_id": atomical_id, "type": "FT"}

    # before is_custom_coloring_activated
    # input[0] = 11001 ft
    # output[0] 11000 ft
    # burn 1 ft
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        {},
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        False,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert ft_output_blueprint.outputs[0]["atomicals"][subject_atomical_id].atomical_value == 11000
    assert len(ft_output_blueprint.outputs) == 1
    assert ft_output_blueprint.fts_burned != {}
    assert ft_output_blueprint.first_atomical_id == subject_atomical_id
    assert blueprint_builder.get_are_fts_burned() == True

    # after is_custom_coloring_activated
    # input[0] = 11001 ft
    # output[0] 11000 ft
    # burn 1 ft
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        {},
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert ft_output_blueprint.outputs[0]["atomicals"][subject_atomical_id].atomical_value == 11000
    assert len(ft_output_blueprint.outputs) == 1
    assert ft_output_blueprint.fts_burned != {}
    assert ft_output_blueprint.first_atomical_id == subject_atomical_id
    assert blueprint_builder.get_are_fts_burned() == True


def test_spends_single_ft_partially_colored_transfer():
    raw_tx_str = "0200000000010cb2906891f279f9c1dc3212f48f2c53b578b7792189a3bbffcde428c4a1d37d5c0000000000ffffffffbe5c19b092cec25d63dfc7b8902c516a8819606d7fcc01265641624940f2107c0000000000ffffffff5cbe08afbae6872b9c4c9c8e257cbd592ff21e34bbd17f7e3391b2a97a3757cd0000000000ffffffffa39bfec965ef9081361c85267ce6ab16e71e7b1bee386cdd7026132bd9e5ad0f0000000000ffffffffcc63fb9dbec22b0747627db00823c153d9711c8650fafece21932224f8d464d50000000000ffffffff09232c3e2c6062c03c8ac2e9874f794b9c59ac5e13a39709ae7a41cb35201b960000000000ffffffff0ca0e7c8ef0aaac310832434dda520a67f6f0ee624e38d3ff0132b1b1b02398c0000000000ffffffff7ccf3abf84161ddb6cd22243ef1b16f8ddf4ae9b59f3e8c7ae314e5e571d79ba0000000000ffffffff09e1d9d28c06d487c82b351d88e4bdb932a63d4989d3aabe603bba04e5c646c00000000000ffffffff54990216d2ba6797c6d555774f02de5de7d277fefd306588b092ec145c5644750000000000ffffffff5aca52eeba8a032bd0a36ef2ae23f3c7948a12e424df0f450b0aa2fa0cb1b1630000000000ffffffff45cee1dc386b8996c084ed0ebf251c012d9e3c531f29c5c81856b947f1b61a4a0000000000ffffffff01f82a00000000000022512032180020ce893cf7a5b3b29f010dfb88af61ffc975f462d1d01c196463aa54240140d7f79372cb379f1f3362d70d0b6b9eaa25c2d671e337d5b613bba07c9568c55733fa8e117153e614ccb2f06ff6192452dee57855679a7100d64b3d58b894cc6d01404932d53958e4449d4ebd1680713405f6b8ce5bcc9fcb2e51a7142e1ff299bac530b19097c597e12854ae5f2baeab17679de622e44745a12b5d9fe173fb8483bb0140684cc8ce62b2b11d58b374fba82c6c9d0a74fd21bda8255e60fcf1a37c99c182bce23405709a173fdc7647c8da70deb1097724a11547b830896825b3f35f49630140d7c76f8a78c43d5e63f64566a18c1a97cb045d9bc4d515c5f50e9a04b3b98848d08e7539a9cc5a33592de05112ae5079f7051cad315faa3805b41e15ab553bd00140c2977fe811c8a853d422288194043ee70616d7ba64d184f2bb70427622e8d5a3cd46042dc73ef2c546be23e3ecf5df9ba102462ca5e98c73e8bc10699c40b7490140a3fe2d0bd549e56b9b8a6bed011cdf905e191234d23facf9cbce9fca698ece58c9904d2a41f4b2ddd19a498ef327661596e16aa5a48c967e3ecbc8f38600f3280140bce200f9d28e1751c8b4c85366062637d1297a22e4b65d4bc78702a7ccb1cba668bbf7415cf436928f353a34dd16949da78d498708ff6ca581fd7eed1cb8df7b0140419eba31f213b531b7981cb317f24eb9ee952384807304a52841b318b0b65ec655d7dbf009e750d2c4a214d23614b57c3cc71f03be90de90482c307d99f8e4d5014050bf388db2ccbb2c1d0ae7c043be5fc8996050abf6d3727531af124d2c6e11855de0333b0e7bd62911fdda0e481dc9cd20790286856bd5932c969901ef21381f0140325a460a4e241e78a24fe2a830363710a11e26c53307611eb90b6ea19db5472680f2ed04b13b5582b730cd96524e9ff89fa16e0942b841f61c4454a06e36c3b3014057901a51a226de41d6e7e6df666ada1ce0f14ec5c535418d10fbc8461d988cdbf70f0b8e8441743a6a39c184aa9ee95cfe11f7ae8c75720a678d4184aa7a7d1c01403fe06d7121381d81589a74a7927d75769eb70132585df7309f817d30c69be79d74a7a383ad7dab079436276f7388cdddbfd80add939b6a6cc3d194f0d6d2ccd800000000"
    raw_tx = bytes.fromhex(raw_tx_str)
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x01"
    )
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    atomicals_spent_at_inputs = {
        0: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 11001, "atomical_value": 500},
            }
        ]
    }

    def mock_mint_fetcher(self, atomical_id):
        return {"atomical_id": atomical_id, "type": "FT"}

    # input[0] = 500 ft
    # output[0] 500 ft
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        {},
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert ft_output_blueprint.outputs[0]["atomicals"][subject_atomical_id].atomical_value == 500
    assert len(ft_output_blueprint.outputs) == 1
    assert ft_output_blueprint.fts_burned == {}
    assert ft_output_blueprint.first_atomical_id == subject_atomical_id
    assert blueprint_builder.get_are_fts_burned() == False


def test_spends_multiple_ft_partially_colored_merged():
    raw_tx_str = "0200000000010cb2906891f279f9c1dc3212f48f2c53b578b7792189a3bbffcde428c4a1d37d5c0000000000ffffffffbe5c19b092cec25d63dfc7b8902c516a8819606d7fcc01265641624940f2107c0000000000ffffffff5cbe08afbae6872b9c4c9c8e257cbd592ff21e34bbd17f7e3391b2a97a3757cd0000000000ffffffffa39bfec965ef9081361c85267ce6ab16e71e7b1bee386cdd7026132bd9e5ad0f0000000000ffffffffcc63fb9dbec22b0747627db00823c153d9711c8650fafece21932224f8d464d50000000000ffffffff09232c3e2c6062c03c8ac2e9874f794b9c59ac5e13a39709ae7a41cb35201b960000000000ffffffff0ca0e7c8ef0aaac310832434dda520a67f6f0ee624e38d3ff0132b1b1b02398c0000000000ffffffff7ccf3abf84161ddb6cd22243ef1b16f8ddf4ae9b59f3e8c7ae314e5e571d79ba0000000000ffffffff09e1d9d28c06d487c82b351d88e4bdb932a63d4989d3aabe603bba04e5c646c00000000000ffffffff54990216d2ba6797c6d555774f02de5de7d277fefd306588b092ec145c5644750000000000ffffffff5aca52eeba8a032bd0a36ef2ae23f3c7948a12e424df0f450b0aa2fa0cb1b1630000000000ffffffff45cee1dc386b8996c084ed0ebf251c012d9e3c531f29c5c81856b947f1b61a4a0000000000ffffffff01f82a00000000000022512032180020ce893cf7a5b3b29f010dfb88af61ffc975f462d1d01c196463aa54240140d7f79372cb379f1f3362d70d0b6b9eaa25c2d671e337d5b613bba07c9568c55733fa8e117153e614ccb2f06ff6192452dee57855679a7100d64b3d58b894cc6d01404932d53958e4449d4ebd1680713405f6b8ce5bcc9fcb2e51a7142e1ff299bac530b19097c597e12854ae5f2baeab17679de622e44745a12b5d9fe173fb8483bb0140684cc8ce62b2b11d58b374fba82c6c9d0a74fd21bda8255e60fcf1a37c99c182bce23405709a173fdc7647c8da70deb1097724a11547b830896825b3f35f49630140d7c76f8a78c43d5e63f64566a18c1a97cb045d9bc4d515c5f50e9a04b3b98848d08e7539a9cc5a33592de05112ae5079f7051cad315faa3805b41e15ab553bd00140c2977fe811c8a853d422288194043ee70616d7ba64d184f2bb70427622e8d5a3cd46042dc73ef2c546be23e3ecf5df9ba102462ca5e98c73e8bc10699c40b7490140a3fe2d0bd549e56b9b8a6bed011cdf905e191234d23facf9cbce9fca698ece58c9904d2a41f4b2ddd19a498ef327661596e16aa5a48c967e3ecbc8f38600f3280140bce200f9d28e1751c8b4c85366062637d1297a22e4b65d4bc78702a7ccb1cba668bbf7415cf436928f353a34dd16949da78d498708ff6ca581fd7eed1cb8df7b0140419eba31f213b531b7981cb317f24eb9ee952384807304a52841b318b0b65ec655d7dbf009e750d2c4a214d23614b57c3cc71f03be90de90482c307d99f8e4d5014050bf388db2ccbb2c1d0ae7c043be5fc8996050abf6d3727531af124d2c6e11855de0333b0e7bd62911fdda0e481dc9cd20790286856bd5932c969901ef21381f0140325a460a4e241e78a24fe2a830363710a11e26c53307611eb90b6ea19db5472680f2ed04b13b5582b730cd96524e9ff89fa16e0942b841f61c4454a06e36c3b3014057901a51a226de41d6e7e6df666ada1ce0f14ec5c535418d10fbc8461d988cdbf70f0b8e8441743a6a39c184aa9ee95cfe11f7ae8c75720a678d4184aa7a7d1c01403fe06d7121381d81589a74a7927d75769eb70132585df7309f817d30c69be79d74a7a383ad7dab079436276f7388cdddbfd80add939b6a6cc3d194f0d6d2ccd800000000"
    raw_tx = bytes.fromhex(raw_tx_str)

    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x01"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x00"
    )

    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    atomicals_spent_at_inputs = {
        0: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 501},
            }
        ],
        1: [
            {
                "atomical_id": subject_atomical_id2,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 3000, "atomical_value": 3000},
            }
        ],
        2: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 1000},
            }
        ],
        3: [
            {
                "atomical_id": subject_atomical_id2,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
        4: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
        5: [
            {
                "atomical_id": subject_atomical_id2,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
        6: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
        7: [
            {
                "atomical_id": subject_atomical_id2,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
        8: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
        9: [
            {
                "atomical_id": subject_atomical_id2,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
        10: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2000, "atomical_value": 2000},
            }
        ],
    }

    def mock_mint_fetcher(self, atomical_id):
        return {"atomical_id": atomical_id, "type": "FT"}

    # input[0] = 501 ft
    # .....
    # input[9] = 2000 ft2
    # input[10] = 2000 ft
    # output[0] 9501 ft and 11000 ft2
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        {},
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 1
    assert ft_output_blueprint.first_atomical_id == subject_atomical_id
    assert ft_output_blueprint.outputs[0]["atomicals"][subject_atomical_id].atomical_value == 9501
    assert ft_output_blueprint.outputs[0]["atomicals"][subject_atomical_id2].atomical_value == 11000
    assert len(ft_output_blueprint.fts_burned) == 0
    assert ft_output_blueprint.cleanly_assigned == False
    assert blueprint_builder.get_are_fts_burned() == False


def test_spends_multiple_nft_and_ft_partially_colored_merged():
    # txid = "e9b48c8ea8a3164062c6c84b920dadc88d4782758a68f241adcd22bc00040323"
    raw_tx_str = "0100000000010213ac24b68388e0e32f3b19e95764c67d03b151d1f524eb07bc6e4f2790a3b7f00000000000ffffffff2423c79220c41bd904699aada54868e5c5aecb15168971964c6f5950a7b1d6860000000000ffffffff03e80300000000000022512011b6ce99eab0d8873d787e99e68a351358228893cdf1049ac48aae51391598abe80300000000000022512011b6ce99eab0d8873d787e99e68a351358228893cdf1049ac48aae51391598abe80300000000000022512011b6ce99eab0d8873d787e99e68a351358228893cdf1049ac48aae51391598ab03401aaa5ca0d475dcec02867f28f687494a639b3b43aff0a776c68d94f8cd3e987bb08a3463d8ab937f18f5dadfc916337b2df98cdd700b8514c6fdaff7f5ddffc975201764381bc0b54064cc55a0dda055c5e9875e5cdd7a7c1452d9b93d6015546170ac00630461746f6d017948a178423935323765666134333236323633366438663539313766633736336662646430393333336534623338376166643664346564376139303561313237623237623469301903e86821c01764381bc0b54064cc55a0dda055c5e9875e5cdd7a7c1452d9b93d60155461700140101db7c999f69c7f551d6800341a75ae659e8c100d1bb116b0935afc9ac3aec69bb97eed3ea72fa75912401400aa53f85f8a862f0f672620f31c5e704d8b4d5c00000000"
    raw_tx = bytes.fromhex(raw_tx_str)
    ft_atomical_id = b'\x13Jv:\xb1\xad\x9a\xaf\x8a#[7\xa9s\xc0\xcc\xb2\xca\xe1"\x05Y\xc8s\x87\x11\xcc\x90W\xe2\x88\x88\x00\x00\x00\x00'
    nft_atomical_id = (
        b"\xb4'{\x12Z\x90z\xed\xd4\xd6\xaf\x87\xb3\xe43\x93\xd0\xbd?v\xfc\x17Y\x8fmcb2\xa4\xef'\x95\x00\x00\x00\x00"
    )
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    atomicals_spent_at_inputs = {
        1: [
            {
                "atomical_id": ft_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1100, "atomical_value": 1100},
            },
            {
                "atomical_id": nft_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1100, "atomical_value": 1100},
            },
        ],
    }

    def mock_mint_fetcher(self, atomical_id):
        if self == ft_atomical_id:
            return {"atomical_id": atomical_id, "type": "FT"}
        return {"atomical_id": atomical_id, "type": "NFT"}

    # input[0] = 1100 nft and 1100 ft
    # output[0] 1000 nft and 1000 ft
    # output[1] 100 ft
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        {},
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 1
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 2
    assert ft_output_blueprint.outputs[1]["atomicals"][ft_atomical_id].atomical_value == 100
    assert len(ft_output_blueprint.fts_burned) == 0
    assert ft_output_blueprint.cleanly_assigned == False
    assert blueprint_builder.get_are_fts_burned() == False


def test_spends_ft_split_one_token():
    # txid = "781e969ed7ac7c135e897e14120952316054d604f7088727adc5068f5d4c679e"
    raw_tx_str = "020000000001036156b41db4932212ebb5ec023d364e147469fe19f72df554b0619c128303095a0000000000fdffffff2303b8203a140e142563cd4bdbee802175ed61b1ae1e2dde62b1aee4eb97d8100000000000fdffffffa8517f14bc5bbb0808304900162f00651ee16ae9393f302348cb6b818df09def0200000000fdffffff03ae0500000000000022512061f023b192540b40b459e9aa62aedceb874e6ea599723d21aa7274e5ddc3be89cf9605000000000022512061f023b192540b40b459e9aa62aedceb874e6ea599723d21aa7274e5ddc3be898813000000000000225120147a5a8865130d15d399a57be23f8f3a1687314972d6ea1e5e34902fb8cb022101402b081e67f42e55db22ffbcfa4ab827d613afe538fd02a7ce3e7a6e5038d365166bfad0dc20a87ec14c7e154b158cc37c71d19f5df1bc3423d543c75c921c44b40140471af0ccb8cfa9e6f7194462a6853fdf9ab5f6f48b39777a9de971b052550639c5068dac18457a790f10a7fd09f69d6b25c604be8106f2ed6fcd6c3257979f8501405726e2c31d65de8a5da3796fe51fefc14cd58386684bfa8b76f7609d4b33098cf0e26d31b9d41711e275d0eb169e9705bfdbc88784d1a0c54b5e85d21363a98000000000"
    raw_tx = bytes.fromhex(raw_tx_str)
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x01"
    )
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    atomicals_spent_at_inputs = {
        0: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 900, "atomical_value": 900},
            }
        ],
        1: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 555, "atomical_value": 555},
            }
        ],
    }

    def mock_mint_fetcher(self, atomical_id):
        return {"atomical_id": atomical_id, "type": "FT"}

    # before is_custom_coloring_activated
    # input[0] = 900 ft
    # input[1] = 555 ft
    # output[0] = 1454 ft
    # burn 1 ft
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        {},
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        False,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 1
    assert ft_output_blueprint.first_atomical_id == subject_atomical_id
    assert blueprint_builder.get_are_fts_burned() == True

    # after is_custom_coloring_activated
    # input[0] = 900 ft
    # input[1] = 555 ft
    # output[0] = 1454 ft
    # output[1] = 1 ft
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        {},
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 2
    assert ft_output_blueprint.outputs[1]["atomicals"][subject_atomical_id].atomical_value == 1
    assert ft_output_blueprint.first_atomical_id == subject_atomical_id
    assert blueprint_builder.get_are_fts_burned() == False

    # before is_custom_coloring_activated
    # input[0] = 900 ft
    # input[1] = 553 ft
    # burn 1453 ft
    atomicals_spent_at_inputs = {
        0: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 900, "atomical_value": 900},
            }
        ],
        1: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 553, "atomical_value": 553},
            }
        ],
    }
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        {},
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        False,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 0
    assert ft_output_blueprint.first_atomical_id == subject_atomical_id
    assert blueprint_builder.cleanly_assigned == False
    assert blueprint_builder.fts_burned == {
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x01": 1453
    }
    assert blueprint_builder.get_are_fts_burned() == True

    # after is_custom_coloring_activated
    # input[0] = 900 ft
    # input[1] = 553 ft
    # ouput[0] 1453 ft partlly colored
    atomicals_spent_at_inputs = {
        0: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 900, "atomical_value": 900},
            }
        ],
        1: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 553, "atomical_value": 553},
            }
        ],
    }
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        {},
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 1
    assert ft_output_blueprint.first_atomical_id == subject_atomical_id
    assert blueprint_builder.cleanly_assigned == False
    assert blueprint_builder.fts_burned == {}
    assert blueprint_builder.get_are_fts_burned() == False


def test_ft_y_split_ft_normal():
    raw_tx_str = "0100000000010213ac24b68388e0e32f3b19e95764c67d03b151d1f524eb07bc6e4f2790a3b7f00000000000ffffffff2423c79220c41bd904699aada54868e5c5aecb15168971964c6f5950a7b1d6860000000000ffffffff03e80300000000000022512011b6ce99eab0d8873d787e99e68a351358228893cdf1049ac48aae51391598abe80300000000000022512011b6ce99eab0d8873d787e99e68a351358228893cdf1049ac48aae51391598abe80300000000000022512011b6ce99eab0d8873d787e99e68a351358228893cdf1049ac48aae51391598ab03401aaa5ca0d475dcec02867f28f687494a639b3b43aff0a776c68d94f8cd3e987bb08a3463d8ab937f18f5dadfc916337b2df98cdd700b8514c6fdaff7f5ddffc975201764381bc0b54064cc55a0dda055c5e9875e5cdd7a7c1452d9b93d6015546170ac00630461746f6d017948a178423935323765666134333236323633366438663539313766633736336662646430393333336534623338376166643664346564376139303561313237623237623469301903e86821c01764381bc0b54064cc55a0dda055c5e9875e5cdd7a7c1452d9b93d60155461700140101db7c999f69c7f551d6800341a75ae659e8c100d1bb116b0935afc9ac3aec69bb97eed3ea72fa75912401400aa53f85f8a862f0f672620f31c5e704d8b4d5c00000000"
    raw_tx = bytes.fromhex(raw_tx_str)
    subject_atomical_id = b'\x13Jv:\xb1\xad\x9a\xaf\x8a#[7\xa9s\xc0\xcc\xb2\xca\xe1"\x05Y\xc8s\x87\x11\xcc\x90W\xe2\x88\x88\x00\x00\x00\x00'
    subject_atomical_id1 = (
        b"\xb4'{\x12Z\x90z\xed\xd4\xd6\xaf\x87\xb3\xe43\x93\xd0\xbd?v\xfc\x17Y\x8fmcb2\xa4\xef'\x95\x00\x00\x00\x00"
    )
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    operation_found_at_inputs = parse_protocols_operations_from_witness_array(tx, tx_hash, True)
    # split two ft from one utxo
    # input[1] = 1000 ft and 1000 ft1
    # output[0] = 1000 ft
    # output[1] = 1000 ft
    atomicals_spent_at_inputs = {
        1: [
            {
                "atomical_id": subject_atomical_id1,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            },
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            },
        ]
    }

    def mock_mint_fetcher(self, atomical_id):
        return {"atomical_id": atomical_id, "type": "FT"}

    # before is_custom_coloring_activated
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operation_found_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        False,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 2
    assert ft_output_blueprint.fts_burned == {}
    assert blueprint_builder.get_are_fts_burned() == False

    # before is_custom_coloring_activated
    # it will be burned
    # input[1] = 1100 ft and 1000 ft1
    # output[0] = 1000 ft
    # output[1] = 1000 ft1
    # burn 100 ft
    atomicals_spent_at_inputs = {
        1: [
            {
                "atomical_id": subject_atomical_id1,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            },
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1100, "atomical_value": 1100},
            },
        ]
    }
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operation_found_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        False,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 2
    assert ft_output_blueprint.fts_burned != {}
    assert blueprint_builder.get_are_fts_burned() == True

    # after is_custom_coloring_activated
    # no burned, partlly colored
    # input[1] = 1100 ft and 1000 ft1
    # output[0] = 1000 ft
    # output[1] = 1000 ft1
    # output[2] = 100 ft1
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operation_found_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 2
    assert ft_output_blueprint.fts_burned == {}
    assert blueprint_builder.get_are_fts_burned() == False

    # after is_custom_coloring_activated and set atomical_value > utxo value
    # in this case skip value in operation_found_at_inputs match the atomical_value
    # skip subject_atomical_id for 1000 in operation_found_at_inputs
    # input[1] = 1000 ft and 1100 ft1
    # output[0] = 1000 ft
    # output[1] = 1000 ft1
    # output[2] = 100 ft1
    atomicals_spent_at_inputs = {
        1: [
            {
                "atomical_id": subject_atomical_id1,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1100, "atomical_value": 1100},
            },
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            },
        ]
    }
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operation_found_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 3
    assert ft_output_blueprint.fts_burned == {}
    assert blueprint_builder.get_are_fts_burned() == False

    # after is_custom_coloring_activated and set atomical_value > utxo value
    # in this case skip value in operation_found_at_inputs *not match* the atomical_value
    # try to split, but will not cause burn.
    # input[1] = 1100 ft and 1100 ft1
    # output[0] = 1000 ft
    # output[1] = 100ft and 1000 ft1
    # output[2] = 100 ft1
    atomicals_spent_at_inputs = {
        1: [
            {
                "atomical_id": subject_atomical_id1,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1100, "atomical_value": 1100},
            },
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1100, "atomical_value": 1100},
            },
        ]
    }
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operation_found_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 3
    assert ft_output_blueprint.fts_burned == {}
    assert blueprint_builder.get_are_fts_burned() == False

    # after is_custom_coloring_activated and set atomical_value > all utxo value
    # in this case skip value in operation_found_at_inputs match the atomical_value
    # it will be burn
    # input[1] = 1000 ft and 2100 ft1
    # output[0] = 1000 ft
    # output[1] = 1000 ft1
    # output[2] = 1000 ft1
    # burn 100 ft1
    atomicals_spent_at_inputs = {
        1: [
            {
                "atomical_id": subject_atomical_id1,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2100, "atomical_value": 2100},
            },
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            },
        ]
    }
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operation_found_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 3
    assert ft_output_blueprint.fts_burned != {}
    assert blueprint_builder.get_are_fts_burned() == True


def test_y_split_nft_and_ft():
    raw_tx_str = "0100000000010213ac24b68388e0e32f3b19e95764c67d03b151d1f524eb07bc6e4f2790a3b7f00000000000ffffffff2423c79220c41bd904699aada54868e5c5aecb15168971964c6f5950a7b1d6860000000000ffffffff03e80300000000000022512011b6ce99eab0d8873d787e99e68a351358228893cdf1049ac48aae51391598abe80300000000000022512011b6ce99eab0d8873d787e99e68a351358228893cdf1049ac48aae51391598abe80300000000000022512011b6ce99eab0d8873d787e99e68a351358228893cdf1049ac48aae51391598ab03401aaa5ca0d475dcec02867f28f687494a639b3b43aff0a776c68d94f8cd3e987bb08a3463d8ab937f18f5dadfc916337b2df98cdd700b8514c6fdaff7f5ddffc975201764381bc0b54064cc55a0dda055c5e9875e5cdd7a7c1452d9b93d6015546170ac00630461746f6d017948a178423935323765666134333236323633366438663539313766633736336662646430393333336534623338376166643664346564376139303561313237623237623469301903e86821c01764381bc0b54064cc55a0dda055c5e9875e5cdd7a7c1452d9b93d60155461700140101db7c999f69c7f551d6800341a75ae659e8c100d1bb116b0935afc9ac3aec69bb97eed3ea72fa75912401400aa53f85f8a862f0f672620f31c5e704d8b4d5c00000000"
    raw_tx = bytes.fromhex(raw_tx_str)
    nft_atomical_id = b'\x13Jv:\xb1\xad\x9a\xaf\x8a#[7\xa9s\xc0\xcc\xb2\xca\xe1"\x05Y\xc8s\x87\x11\xcc\x90W\xe2\x88\x88\x00\x00\x00\x00'
    ft_atomical_id = (
        b"\xb4'{\x12Z\x90z\xed\xd4\xd6\xaf\x87\xb3\xe43\x93\xd0\xbd?v\xfc\x17Y\x8fmcb2\xa4\xef'\x95\x00\x00\x00\x00"
    )

    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    operation_found_at_inputs = parse_protocols_operations_from_witness_array(tx, tx_hash, True)
    # skip 1000 for ft
    operation_found_at_inputs["payload"]["9527efa43262636d8f5917fc763fbdd09333e4b387afd6d4ed7a905a127b27b4i0"] = 1000
    # if atomical_value <= utxo value
    # if will be fullly colored all total ft
    # input[1] = 1000 nft and 1100 ft
    # output[0] = 1000 nft
    # output[1] = 1000 ft
    # output[2] = 100 ft
    atomicals_spent_at_inputs = {
        1: [
            {
                "atomical_id": ft_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1100, "atomical_value": 1100},
            },
            {
                "atomical_id": nft_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            },
        ]
    }

    def mock_mint_fetcher(self, atomical_id):
        if self == ft_atomical_id:
            return {"atomical_id": atomical_id, "type": "FT"}
        return {"atomical_id": atomical_id, "type": "NFT"}

    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operation_found_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 1
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 2
    assert ft_output_blueprint.outputs[2]["atomicals"][ft_atomical_id].atomical_value == 100
    assert ft_output_blueprint.fts_burned == {}
    assert blueprint_builder.get_are_fts_burned() == False

    # before is_custom_coloring_activated
    # set is_custom_coloring_activated = False
    # it will be burned, because not cleanly_assigned for output[2], and output[1] will colored 1000
    # input[1] = 1000 nft and 1100 ft
    # output[0] = 1000 nft
    # output[1] = 1000 ft
    # burn 100 ft
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operation_found_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        False,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 1
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 1
    assert ft_output_blueprint.fts_burned != {}
    assert blueprint_builder.get_are_fts_burned() == True

    # if atomical_value > utxo value
    # it will be burned
    # set is_custom_coloring_activated = True
    # input[1] = 1000 nft and 2100 ft
    # output[0] = 1000 nft
    # output[1] = 1000 ft
    # output[2] = 1000 ft
    # burn 100 ft
    atomicals_spent_at_inputs = {
        1: [
            {
                "atomical_id": ft_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 2100, "atomical_value": 2100},
            },
            {
                "atomical_id": nft_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            },
        ]
    }
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operation_found_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 1
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 2
    assert ft_output_blueprint.outputs[2]["atomicals"][ft_atomical_id].atomical_value == 1000
    assert ft_output_blueprint.fts_burned != {}
    assert blueprint_builder.get_are_fts_burned() == True


def test_custom_colored_ft_normal():
    raw_tx_str = "0100000000010213ac24b68388e0e32f3b19e95764c67d03b151d1f524eb07bc6e4f2790a3b7f00000000000ffffffff2423c79220c41bd904699aada54868e5c5aecb15168971964c6f5950a7b1d6860000000000ffffffff03e80300000000000022512011b6ce99eab0d8873d787e99e68a351358228893cdf1049ac48aae51391598abe80300000000000022512011b6ce99eab0d8873d787e99e68a351358228893cdf1049ac48aae51391598abe80300000000000022512011b6ce99eab0d8873d787e99e68a351358228893cdf1049ac48aae51391598ab03401aaa5ca0d475dcec02867f28f687494a639b3b43aff0a776c68d94f8cd3e987bb08a3463d8ab937f18f5dadfc916337b2df98cdd700b8514c6fdaff7f5ddffc975201764381bc0b54064cc55a0dda055c5e9875e5cdd7a7c1452d9b93d6015546170ac00630461746f6d017948a178423935323765666134333236323633366438663539313766633736336662646430393333336534623338376166643664346564376139303561313237623237623469301903e86821c01764381bc0b54064cc55a0dda055c5e9875e5cdd7a7c1452d9b93d60155461700140101db7c999f69c7f551d6800341a75ae659e8c100d1bb116b0935afc9ac3aec69bb97eed3ea72fa75912401400aa53f85f8a862f0f672620f31c5e704d8b4d5c00000000"
    raw_tx = bytes.fromhex(raw_tx_str)
    subject_atomical_id = b'\x13Jv:\xb1\xad\x9a\xaf\x8a#[7\xa9s\xc0\xcc\xb2\xca\xe1"\x05Y\xc8s\x87\x11\xcc\x90W\xe2\x88\x88\x00\x00\x00\x00'
    subject_atomical_id1 = (
        b"\xb4'{\x12Z\x90z\xed\xd4\xd6\xaf\x87\xb3\xe43\x93\xd0\xbd?v\xfc\x17Y\x8fmcb2\xa4\xef'\x95\x00\x00\x00\x00"
    )
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    operation_found_at_inputs = parse_protocols_operations_from_witness_array(tx, tx_hash, True)
    # z means costom color
    operation_found_at_inputs["op"] = "z"
    operation_found_at_inputs["payload"] = {
        "9527efa43262636d8f5917fc763fbdd09333e4b387afd6d4ed7a905a127b27b4i0": {
            "0": 200,
            "1": 300,
        },
        "8888e25790cc118773c8590522e1cab2ccc073a9375b238aaf9aadb13a764a13i0": {
            "2": 8000,
            "4": 8000,
        },
    }
    atomicals_spent_at_inputs = {
        1: [
            {
                "atomical_id": subject_atomical_id1,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            },
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            },
        ]
    }

    def mock_mint_fetcher(self, atomical_id):
        return {"atomical_id": atomical_id, "type": "FT"}

    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operation_found_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert ft_output_blueprint.cleanly_assigned == False
    assert len(ft_output_blueprint.outputs) == 3
    assert ft_output_blueprint.fts_burned != {}
    assert blueprint_builder.get_are_fts_burned() == True

    operation_found_at_inputs["payload"] = {
        "9527efa43262636d8f5917fc763fbdd09333e4b387afd6d4ed7a905a127b27b4i0": {
            "1": 1000,
        },
        "8888e25790cc118773c8590522e1cab2ccc073a9375b238aaf9aadb13a764a13i0": {
            "2": 1000,
        },
    }
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operation_found_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert ft_output_blueprint.cleanly_assigned == True
    assert len(ft_output_blueprint.outputs) == 2
    assert ft_output_blueprint.fts_burned == {}
    assert blueprint_builder.get_are_fts_burned() == False


def test_custom_colored_ft_normal1():
    raw_tx_str = "0100000000010258f654e38dee561d45847f45d856ad8cb2d7eafd574521d10ad28b30f44a9e020000000000ffffffffbf6b35d1973a17fc67188ff19731341dafad28a2aac9371c5286c955a6e16c450000000000ffffffff022202000000000000225120d9b4878e9915c8c37149942b02102ed86e462e47f6749424852dc4af89551f212202000000000000225120d9b4878e9915c8c37149942b02102ed86e462e47f6749424852dc4af89551f210340a4334065f27cb80fbf39bd28e634ca9b4e4d7c9b90ed6d575edd9856a664b4352d62e4af96ad11e8aabde952994d8fcb5dd2233ca54100f42045fe63bee9819c7d20c145f972a018b8c401ffd9181a1299a319aee1d55bf2d3393bcd659f06830a78ac00630461746f6d017a4c4fa17842363738376633396235643266633032306562306638653638636439323566323937303635633563383263383664313735636365316139626561613431313233396930a2613018c8613119015a6821c0c145f972a018b8c401ffd9181a1299a319aee1d55bf2d3393bcd659f06830a7801407e04393dddd9e6f899b581a64d26be40b9c148bf1696d99a962dd5257af023ad651efdd4d850819f5eb44e5c281ffb458d59382032248eecf39eb86d4d5dfcb300000000"
    raw_tx = bytes.fromhex(raw_tx_str)
    subject_atomical_id = (
        b"9\x12A\xaa\xbe\xa9\xe1\xccu\xd1\x86,\xc8\xc5ep)_\x92\xcdh\x8e\x0f\xeb \xc0/]\x9b\xf3\x87g\x00\x00\x00\x00"
    )
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    operation_found_at_inputs = parse_protocols_operations_from_witness_array(tx, tx_hash, True)
    atomicals_spent_at_inputs = {
        0: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 546, "atomical_value": 546},
            }
        ]
    }

    def mock_mint_fetcher(self, atomical_id):
        return {"atomical_id": atomical_id, "type": "FT"}

    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operation_found_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert ft_output_blueprint.first_atomical_id == subject_atomical_id
    assert ft_output_blueprint.cleanly_assigned == False
    assert len(ft_output_blueprint.outputs) == 2
    assert ft_output_blueprint.fts_burned == {}
    assert blueprint_builder.get_are_fts_burned() == False


def test_custom_colored_nft_normal():
    raw_tx_str = "0100000000010258f654e38dee561d45847f45d856ad8cb2d7eafd574521d10ad28b30f44a9e020000000000ffffffffbf6b35d1973a17fc67188ff19731341dafad28a2aac9371c5286c955a6e16c450000000000ffffffff022202000000000000225120d9b4878e9915c8c37149942b02102ed86e462e47f6749424852dc4af89551f212202000000000000225120d9b4878e9915c8c37149942b02102ed86e462e47f6749424852dc4af89551f210340a4334065f27cb80fbf39bd28e634ca9b4e4d7c9b90ed6d575edd9856a664b4352d62e4af96ad11e8aabde952994d8fcb5dd2233ca54100f42045fe63bee9819c7d20c145f972a018b8c401ffd9181a1299a319aee1d55bf2d3393bcd659f06830a78ac00630461746f6d017a4c4fa17842363738376633396235643266633032306562306638653638636439323566323937303635633563383263383664313735636365316139626561613431313233396930a2613018c8613119015a6821c0c145f972a018b8c401ffd9181a1299a319aee1d55bf2d3393bcd659f06830a7801407e04393dddd9e6f899b581a64d26be40b9c148bf1696d99a962dd5257af023ad651efdd4d850819f5eb44e5c281ffb458d59382032248eecf39eb86d4d5dfcb300000000"
    raw_tx = bytes.fromhex(raw_tx_str)
    subject_atomical_id = (
        b"9\x12A\xaa\xbe\xa9\xe1\xccu\xd1\x86,\xc8\xc5ep)_\x92\xcdh\x8e\x0f\xeb \xc0/]\x9b\xf3\x87g\x00\x00\x00\x00"
    )
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    atomicals_spent_at_inputs = {
        0: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 1000, "atomical_value": 1000},
            }
        ]
    }

    def mock_mint_fetcher(self, atomical_id):
        return {
            "atomical_id": atomical_id,
            # set for nft
            "type": "NFT",
        }

    operation_found_at_inputs = parse_protocols_operations_from_witness_array(tx, tx_hash, True)
    # try to custom nft to output 1
    operation_found_at_inputs["payload"]["6787f39b5d2fc020eb0f8e68cd925f297065c5c82c86d175cce1a9beaa411239i0"] = {
        1: 1000
    }
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operation_found_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 1
    assert len(nft_output_blueprint.nfts_burned) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert ft_output_blueprint.cleanly_assigned is True
    assert len(ft_output_blueprint.outputs) == 0
    assert ft_output_blueprint.fts_burned == {}
    assert blueprint_builder.get_are_fts_burned() is False

    operation_found_at_inputs["payload"]["6787f39b5d2fc020eb0f8e68cd925f297065c5c82c86d175cce1a9beaa411239i0"] = {
        "1": 546
    }
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operation_found_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 1
    assert len(nft_output_blueprint.nfts_burned) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert ft_output_blueprint.cleanly_assigned is True
    assert len(ft_output_blueprint.outputs) == 0
    assert ft_output_blueprint.fts_burned == {}
    assert blueprint_builder.get_are_fts_burned() is False

    operation_found_at_inputs["payload"] = {}
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operation_found_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    assert len(nft_output_blueprint.nfts_burned) == 1
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert ft_output_blueprint.cleanly_assigned is True
    assert len(ft_output_blueprint.outputs) == 0
    assert ft_output_blueprint.fts_burned == {}
    assert blueprint_builder.get_are_fts_burned() is False


def test_partially_colored_spends_are_payments_satisfied_checks():
    raw_tx_str = "02000000000101647760b13086a2f2e77395e474305237afa65ec638dda01132c8c48c8b891fd00000000000ffffffff03a8610000000000002251208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749679a861000000000000225120ed2ec645d1749c9b2dba88b1346899c60c82f7a57e6359964393a2bba31450f200000000000000002d6a0461746f6d017024921bd27146f57d42565b373214ae7f6d05fa85c3f73eeb5dd876c4c81be58888000000000140d94db131ec889cb33fc258bc3bb5ace3656597cde88cf51494ae864f171915d262a50af24e3699560116450c4244a99b7d84602b8be1fe4c640250d2202330c800000000"
    raw_tx = bytes.fromhex(raw_tx_str)
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )

    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    atomicals_spent_at_inputs = {
        1: [
            {
                "atomical_id": subject_atomical_id,
                "location_id": b"not_used",
                "data": b"not_used",
                "data_value": {"sat_value": 50000, "atomical_value": 2},
            },
        ],
    }

    def mock_mint_fetcher(self, atomical_id):
        return {"atomical_id": atomical_id, "type": "FT"}

    operations_at_inputs = {}
    blueprint_builder = AtomicalsTransferBlueprintBuilder(
        MockLogger(),
        atomicals_spent_at_inputs,
        operations_at_inputs,
        tx_hash,
        tx,
        mock_mint_fetcher,
        True,
        True,
    )
    nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
    assert len(nft_output_blueprint.outputs) == 0
    ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
    assert len(ft_output_blueprint.outputs) == 1
    assert ft_output_blueprint.cleanly_assigned == False
    assert blueprint_builder.get_are_fts_burned() == False

    subject_atomical_id_compact = location_id_bytes_to_compact(subject_atomical_id)
    # Empty rules
    rules = {}
    payment_valid = blueprint_builder.are_payments_satisfied(rules)
    assert not payment_valid
    # Valid payment to one output
    rules = {
        "51208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749679": {
            "id": subject_atomical_id_compact,
            "v": 2,
        }
    }
    payment_valid = blueprint_builder.are_payments_satisfied(rules)
    assert payment_valid
    # Invalid payment insufficient amount
    rules = {
        "51208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749679": {
            "id": subject_atomical_id_compact,
            "v": 3,
        }
    }
    payment_valid = blueprint_builder.are_payments_satisfied(rules)
    assert not payment_valid
    # Valid payment higher amount
    rules = {
        "51208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749679": {
            "id": subject_atomical_id_compact,
            "v": 1,
        }
    }
    payment_valid = blueprint_builder.are_payments_satisfied(rules)
    assert payment_valid
    # Invalid payment to wrong address
    rules = {
        "51208a586070907d75b89f1b7bcbe8dd5c623e0143e9b62d5d6759da06a59b749678": {
            "id": subject_atomical_id_compact,
            "v": 2,
        }
    }
    payment_valid = blueprint_builder.are_payments_satisfied(rules)
    assert not payment_valid


def test_parse_operations_from_empty_tap_leafs():
    psbt = (
        "70736274ff01005e010000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffff"
        "ff0122020000000000002251202b2e6c7946ede6a9e76ea8dc599b375a1899cf7ba784754fa9ab91486ad56fb3000000000001012b"
        "62d0000000000000225120ecbc068d696bf671b51d45a892a6777a9e4a624bbb14aa4f3040c1a0d95786b72215c0486ff77b86a935"
        "ed21a35a48ee5fa00cec653dcfcc6f3f93cd9b9232287870963220486ff77b86a935ed21a35a48ee5fa00cec653dcfcc6f3f93cd9b"
        "923228787096ac00630477697a7a013604b4f5493a68c00000"
    )
    tx, tap_leafs = parse_psbt_hex_and_operations(psbt)
    op = parse_atomicals_operations_from_tap_leafs(tap_leafs, True)
    assert isinstance(op, dict)
