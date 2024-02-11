import pytest

from electrumx.lib.atomicals_blueprint_builder import AtomicalsTransferBlueprintBuilder, get_nominal_token_value
from electrumx.lib.coins import Bitcoin
from electrumx.lib.hash import HASHX_LEN, hex_str_to_hash, hash_to_hex_str
from electrumx.lib.tx import Tx, TxInput, TxOutput
from electrumx.lib.avm_factory import AVMFactory

from electrumx.lib.util_atomicals import (
    location_id_bytes_to_compact
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
    avm_factory = AVMFactory(MockLogger(), {}, {})
    assert(avm_factory)

    result = avm_factory.get_modified_atomicals_spent_at_inputs()
    assert(result == {})
   
  
def test_multiple_spends_payable_invalid1():
    raw_tx_str = '0200000000010cb2906891f279f9c1dc3212f48f2c53b578b7792189a3bbffcde428c4a1d37d5c0000000000ffffffffbe5c19b092cec25d63dfc7b8902c516a8819606d7fcc01265641624940f2107c0000000000ffffffff5cbe08afbae6872b9c4c9c8e257cbd592ff21e34bbd17f7e3391b2a97a3757cd0000000000ffffffffa39bfec965ef9081361c85267ce6ab16e71e7b1bee386cdd7026132bd9e5ad0f0000000000ffffffffcc63fb9dbec22b0747627db00823c153d9711c8650fafece21932224f8d464d50000000000ffffffff09232c3e2c6062c03c8ac2e9874f794b9c59ac5e13a39709ae7a41cb35201b960000000000ffffffff0ca0e7c8ef0aaac310832434dda520a67f6f0ee624e38d3ff0132b1b1b02398c0000000000ffffffff7ccf3abf84161ddb6cd22243ef1b16f8ddf4ae9b59f3e8c7ae314e5e571d79ba0000000000ffffffff09e1d9d28c06d487c82b351d88e4bdb932a63d4989d3aabe603bba04e5c646c00000000000ffffffff54990216d2ba6797c6d555774f02de5de7d277fefd306588b092ec145c5644750000000000ffffffff5aca52eeba8a032bd0a36ef2ae23f3c7948a12e424df0f450b0aa2fa0cb1b1630000000000ffffffff45cee1dc386b8996c084ed0ebf251c012d9e3c531f29c5c81856b947f1b61a4a0000000000ffffffff01f82a00000000000022512032180020ce893cf7a5b3b29f010dfb88af61ffc975f462d1d01c196463aa54240140d7f79372cb379f1f3362d70d0b6b9eaa25c2d671e337d5b613bba07c9568c55733fa8e117153e614ccb2f06ff6192452dee57855679a7100d64b3d58b894cc6d01404932d53958e4449d4ebd1680713405f6b8ce5bcc9fcb2e51a7142e1ff299bac530b19097c597e12854ae5f2baeab17679de622e44745a12b5d9fe173fb8483bb0140684cc8ce62b2b11d58b374fba82c6c9d0a74fd21bda8255e60fcf1a37c99c182bce23405709a173fdc7647c8da70deb1097724a11547b830896825b3f35f49630140d7c76f8a78c43d5e63f64566a18c1a97cb045d9bc4d515c5f50e9a04b3b98848d08e7539a9cc5a33592de05112ae5079f7051cad315faa3805b41e15ab553bd00140c2977fe811c8a853d422288194043ee70616d7ba64d184f2bb70427622e8d5a3cd46042dc73ef2c546be23e3ecf5df9ba102462ca5e98c73e8bc10699c40b7490140a3fe2d0bd549e56b9b8a6bed011cdf905e191234d23facf9cbce9fca698ece58c9904d2a41f4b2ddd19a498ef327661596e16aa5a48c967e3ecbc8f38600f3280140bce200f9d28e1751c8b4c85366062637d1297a22e4b65d4bc78702a7ccb1cba668bbf7415cf436928f353a34dd16949da78d498708ff6ca581fd7eed1cb8df7b0140419eba31f213b531b7981cb317f24eb9ee952384807304a52841b318b0b65ec655d7dbf009e750d2c4a214d23614b57c3cc71f03be90de90482c307d99f8e4d5014050bf388db2ccbb2c1d0ae7c043be5fc8996050abf6d3727531af124d2c6e11855de0333b0e7bd62911fdda0e481dc9cd20790286856bd5932c969901ef21381f0140325a460a4e241e78a24fe2a830363710a11e26c53307611eb90b6ea19db5472680f2ed04b13b5582b730cd96524e9ff89fa16e0942b841f61c4454a06e36c3b3014057901a51a226de41d6e7e6df666ada1ce0f14ec5c535418d10fbc8461d988cdbf70f0b8e8441743a6a39c184aa9ee95cfe11f7ae8c75720a678d4184aa7a7d1c01403fe06d7121381d81589a74a7927d75769eb70132585df7309f817d30c69be79d74a7a383ad7dab079436276f7388cdddbfd80add939b6a6cc3d194f0d6d2ccd800000000'
    raw_tx = bytes.fromhex(raw_tx_str)

    subject_atomical_id = b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x01"
    subject_atomical_id2 = b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x00"
    
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    atomicals_spent_at_inputs= {
        0: [{'atomical_id': subject_atomical_id, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 1000, 'exponent': 0}}], 
        1: [{'atomical_id': subject_atomical_id2, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 3000, 'exponent': 0}}], 
        2: [{'atomical_id': subject_atomical_id, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}], 
        3: [{'atomical_id': subject_atomical_id2, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}], 
        4: [{'atomical_id': subject_atomical_id, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}], 
        5: [{'atomical_id': subject_atomical_id2, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}], 
        6: [{'atomical_id': subject_atomical_id, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}], 
        7: [{'atomical_id': subject_atomical_id2, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}], 
        8: [{'atomical_id': subject_atomical_id, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}], 
        9: [{'atomical_id': subject_atomical_id2, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}], 
        10: [{'atomical_id': subject_atomical_id, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}]}
    
    def mock_mint_fetcher(self, atomical_id):
        return {
            'atomical_id': atomical_id,
            'type': 'FT'
        }

    avm_factory = AVMFactory(MockLogger(), atomicals_spent_at_inputs, {
        'op': 'c',
        'payload': {
            'x': 1
        }
    })
    assert avm_factory.process()
    
    result = avm_factory.get_modified_atomicals_spent_at_inputs()
    assert(result == {})

def test_multiple_spends_payable_success():

    raw_tx_str = '0200000000010cb2906891f279f9c1dc3212f48f2c53b578b7792189a3bbffcde428c4a1d37d5c0000000000ffffffffbe5c19b092cec25d63dfc7b8902c516a8819606d7fcc01265641624940f2107c0000000000ffffffff5cbe08afbae6872b9c4c9c8e257cbd592ff21e34bbd17f7e3391b2a97a3757cd0000000000ffffffffa39bfec965ef9081361c85267ce6ab16e71e7b1bee386cdd7026132bd9e5ad0f0000000000ffffffffcc63fb9dbec22b0747627db00823c153d9711c8650fafece21932224f8d464d50000000000ffffffff09232c3e2c6062c03c8ac2e9874f794b9c59ac5e13a39709ae7a41cb35201b960000000000ffffffff0ca0e7c8ef0aaac310832434dda520a67f6f0ee624e38d3ff0132b1b1b02398c0000000000ffffffff7ccf3abf84161ddb6cd22243ef1b16f8ddf4ae9b59f3e8c7ae314e5e571d79ba0000000000ffffffff09e1d9d28c06d487c82b351d88e4bdb932a63d4989d3aabe603bba04e5c646c00000000000ffffffff54990216d2ba6797c6d555774f02de5de7d277fefd306588b092ec145c5644750000000000ffffffff5aca52eeba8a032bd0a36ef2ae23f3c7948a12e424df0f450b0aa2fa0cb1b1630000000000ffffffff45cee1dc386b8996c084ed0ebf251c012d9e3c531f29c5c81856b947f1b61a4a0000000000ffffffff01f82a00000000000022512032180020ce893cf7a5b3b29f010dfb88af61ffc975f462d1d01c196463aa54240140d7f79372cb379f1f3362d70d0b6b9eaa25c2d671e337d5b613bba07c9568c55733fa8e117153e614ccb2f06ff6192452dee57855679a7100d64b3d58b894cc6d01404932d53958e4449d4ebd1680713405f6b8ce5bcc9fcb2e51a7142e1ff299bac530b19097c597e12854ae5f2baeab17679de622e44745a12b5d9fe173fb8483bb0140684cc8ce62b2b11d58b374fba82c6c9d0a74fd21bda8255e60fcf1a37c99c182bce23405709a173fdc7647c8da70deb1097724a11547b830896825b3f35f49630140d7c76f8a78c43d5e63f64566a18c1a97cb045d9bc4d515c5f50e9a04b3b98848d08e7539a9cc5a33592de05112ae5079f7051cad315faa3805b41e15ab553bd00140c2977fe811c8a853d422288194043ee70616d7ba64d184f2bb70427622e8d5a3cd46042dc73ef2c546be23e3ecf5df9ba102462ca5e98c73e8bc10699c40b7490140a3fe2d0bd549e56b9b8a6bed011cdf905e191234d23facf9cbce9fca698ece58c9904d2a41f4b2ddd19a498ef327661596e16aa5a48c967e3ecbc8f38600f3280140bce200f9d28e1751c8b4c85366062637d1297a22e4b65d4bc78702a7ccb1cba668bbf7415cf436928f353a34dd16949da78d498708ff6ca581fd7eed1cb8df7b0140419eba31f213b531b7981cb317f24eb9ee952384807304a52841b318b0b65ec655d7dbf009e750d2c4a214d23614b57c3cc71f03be90de90482c307d99f8e4d5014050bf388db2ccbb2c1d0ae7c043be5fc8996050abf6d3727531af124d2c6e11855de0333b0e7bd62911fdda0e481dc9cd20790286856bd5932c969901ef21381f0140325a460a4e241e78a24fe2a830363710a11e26c53307611eb90b6ea19db5472680f2ed04b13b5582b730cd96524e9ff89fa16e0942b841f61c4454a06e36c3b3014057901a51a226de41d6e7e6df666ada1ce0f14ec5c535418d10fbc8461d988cdbf70f0b8e8441743a6a39c184aa9ee95cfe11f7ae8c75720a678d4184aa7a7d1c01403fe06d7121381d81589a74a7927d75769eb70132585df7309f817d30c69be79d74a7a383ad7dab079436276f7388cdddbfd80add939b6a6cc3d194f0d6d2ccd800000000'
    raw_tx = bytes.fromhex(raw_tx_str)

    subject_atomical_id = b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x01"
    subject_atomical_id2 = b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x00"
    
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    atomicals_spent_at_inputs= {
        0: [{'atomical_id': subject_atomical_id, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 1000, 'exponent': 0}}], 
        1: [{'atomical_id': subject_atomical_id2, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 3000, 'exponent': 0}}], 
        2: [{'atomical_id': subject_atomical_id, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}], 
        3: [{'atomical_id': subject_atomical_id2, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}], 
        4: [{'atomical_id': subject_atomical_id, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}], 
        5: [{'atomical_id': subject_atomical_id2, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}], 
        6: [{'atomical_id': subject_atomical_id, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}], 
        7: [{'atomical_id': subject_atomical_id2, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}], 
        8: [{'atomical_id': subject_atomical_id, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}], 
        9: [{'atomical_id': subject_atomical_id2, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}], 
        10: [{'atomical_id': subject_atomical_id, 'location_id': b'not_used', 'data': b'not_used', 'data_ex': {'value': 2000, 'exponent': 0}}]}
    
    def mock_mint_fetcher(self, atomical_id):
        return {
            'atomical_id': atomical_id,
            'type': 'FT'
        }

    avm_factory = AVMFactory(MockLogger(), atomicals_spent_at_inputs, {})
    result = avm_factory.get_modified_atomicals_spent_at_inputs()
    assert(result == {s})
    
     
def test_multiple_spends_non_payable_fail():
    # Check that when sending to non payable that the operation is considered invalid and atomicals are not captured
    assert(False)