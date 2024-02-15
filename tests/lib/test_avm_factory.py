import pytest

from electrumx.lib.atomicals_blueprint_builder import AtomicalsTransferBlueprintBuilder, get_nominal_token_value
from electrumx.lib.coins import Bitcoin
from electrumx.lib.hash import HASHX_LEN, hex_str_to_hash, hash_to_hex_str
from electrumx.lib.tx import Tx, TxInput, TxOutput
from electrumx.lib.avm_factory import AVMFactory, AuthorizedCallFactory

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
   
def test_found_callable_variations():
    subject_atomical_id = b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x01"
    call_data = {}
    call_data[subject_atomical_id] = {
        'm': 'deposit'
    }
    structure = {
        'op': 'nft',
        'payload': {
            'args': {
                'call': {
                    'ids': call_data
                }
            }
        }
    }
    avm_factory = AVMFactory(MockLogger(), {}, structure)
    assert(avm_factory.found_callable())
    
    structure['payload']['args']['call']['ids'] = {
        'fieldinvalid': {}
    }
    avm_factory = AVMFactory(MockLogger(), {}, structure)
    assert(not avm_factory.found_callable())

    no_method = {}
    no_method[subject_atomical_id] = {
        'not': 'deposit'
    }
    structure['payload']['args']['call']['ids'] = no_method
    avm_factory = AVMFactory(MockLogger(), {}, structure)
    assert(not avm_factory.found_callable())
    bad_method = {}
    bad_method[subject_atomical_id] = {
        'm': 33
    }
    structure['payload']['args']['call']['ids'] = bad_method
    avm_factory = AVMFactory(MockLogger(), {}, structure)
    assert(not avm_factory.found_callable())

    bad_method_value = {}
    bad_method_value[subject_atomical_id] = {
        'm': ''
    }
    structure['payload']['args']['call']['ids'] = bad_method_value
    avm_factory = AVMFactory(MockLogger(), {}, structure)
    assert(not avm_factory.found_callable())
    
    structure['payload']['args']['call']['ids'] = {}
    avm_factory = AVMFactory(MockLogger(), {}, structure)
    assert(not avm_factory.found_callable())
    
    del structure['payload']['args']['call']['ids']
    avm_factory = AVMFactory(MockLogger(), {}, structure)
    assert(not avm_factory.found_callable())

    del structure['payload']['args']['call']
    avm_factory = AVMFactory(MockLogger(), {}, structure)
    assert(not avm_factory.found_callable())
     
def test_multiple_spends_non_payable_fail():
    # Check that when sending to non payable that the operation is considered invalid and atomicals are not captured
    assert(False)

def test_get_call_method_bytes_invalid1():
    subject_atomical_id = b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x00\x00\x00\x01"
    call_data = {}
    call_data[subject_atomical_id] = {
        'm': 'deposit'
    }
    structure = {
        'op': 'nft',
        'payload': {
            'args': {
                'call': {
                    'ids': call_data
                }
            }
        },
        'other_input_ops': [

        ]
    }
    op_data = {
        'op': 'nft',
        'payload': {
            'args': {
                'call': {
                    'ids': call_data
                }
            }
        },
        'other_input_ops': [
            {
                'op': 's',
                'payload': {
                    'args': {
                        'p': b'pubkey',
                        'sig': b'sig'
                    }
                }
            }
        ]
    }
    factory = AuthorizedCallFactory(op_data)
    authorized_sigs = {}
    assert(factory.get_public_key_sig_map() == authorized_sigs)
    expected_call_method_vector = b'x'
    assert(factory.get_call_method_bytes() == expected_call_method_vector)
        