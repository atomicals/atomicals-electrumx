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
    subject_atomical_id = b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x01"
    call_data = {}
    call_data[subject_atomical_id] = {
        'm': 'deposit'
    }
    avm_factory = AVMFactory(MockLogger(), {}, {
        'op': 'nft',
        'payload': {
            'args': {
                'call': {
                    'ids': call_data
                }
            }
        }
    })
    assert(avm_factory.found_callable())
 
     
def test_multiple_spends_non_payable_fail():
    # Check that when sending to non payable that the operation is considered invalid and atomicals are not captured
    assert(False)