import pytest

from electrumx.lib.coins import Bitcoin
from electrumx.lib.hash import hex_str_to_hash

from electrumx.lib.avm.avm import (
    AVMFactory,
    RequestBlockchainContext,
    RequestTxContext,
    ReactorContext
)
from cbor2 import dumps, loads
coin = Bitcoin

class MockLogger:
    def debug(self, msg):
        return 
    def info(self, msg):
        return 
    def warning(self, msg):
        return 
    
def mock_mint_fetcher(atomical_id):
    return {
    }

mock_current_header = '000000209174c9f2757e2647733c9ab69c133b90257f85ce7e9c0100000000000000000096e490f16d161416bef825bd4716b0914f344be5835cf6a8f0de89288a6c440391af0566d3620317aca8414a'
mock_headers = {
    '840012': mock_current_header
}
mock_blockchain_context = RequestBlockchainContext(mock_headers, 840012)
mock_empty_reactor_context = ReactorContext(None,  dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
mock_rawtx2 = bytes.fromhex('0100000000010156d0f907b0a3385095afb426f46762f4305f39c30b626753b0365c51307f6bac0000000000ffffffff01e803000000000000225120c2529c35bacd75646eb3135ca1270325ba2bab5d473b7c8a1eab54b21deea86e034090e7d4e121a12d1ec63820af4d59663a54c31ca4da6dd861257b728a69c8f61cfad799fce6fc6388eba63e02eca4a3c7df82fa055cd6c2e5c771749c71744a0474209f76f4e90e426cae195e7092cf8ec81d3005a90574e6d0532c679983ad79d7eaac00630461746f6d036e657745a46170667365636f6e64626f70666465706c6f796461726773a36474696d651a66845c51656e6f6e63650068626974776f726b636161646e616d6569636f6e7472616374316821c09f76f4e90e426cae195e7092cf8ec81d3005a90574e6d0532c679983ad79d7ea00000000')
mock_tx2, mock_tx_hash2 = coin.DESERIALIZER(mock_rawtx2, 0).read_tx_and_hash()

# Note this does not work because the avm core does not correct return the witness sript from some problem with unserializing rawtx
def test_execute_deploy_script_OP_INPUTWITNESSBYTECODE_provide_witness():
    protocol_mint_data = {
        'p': 'ppp',
        'code': bytes.fromhex('51cc0377112287'),
        'fn': [
            {
                'name': 'ctor',
                'params': [
                ]
            }
        ]
    }
    avm = AVMFactory(MockLogger(), mock_mint_fetcher, mock_blockchain_context, protocol_mint_data)
    payload = {
        'op': 'deploy',
        'p': 'ppp',
        'args': {
        }
    }
    atomicals_spent_at_inputs = {}
    request_tx_context = RequestTxContext(coin, mock_tx_hash2, mock_tx2, payload, bytes.fromhex('771122'))

    deploy_command = avm.create_deploy_command(request_tx_context, atomicals_spent_at_inputs, mock_empty_reactor_context)
    assert(deploy_command.is_valid)
    assert(deploy_command.unlock_script.hex() == '')
    assert(deploy_command.lock_script.hex() == '51cc0377112287')

    result = deploy_command.execute() 
    assert result.success 


 # Note this does not work because the avm core does not correct return the witness sript from some problem with unserializing rawtx
def test_execute_deploy_script_OP_INPUTWITNESSBYTECODE_no_witness():
    protocol_mint_data = {
        'p': 'ppp',
        'code': bytes.fromhex('51cc0087'),
        'fn': [
            {
                'name': 'ctor',
                'params': [
                ]
            }
        ]
    }
    avm = AVMFactory(MockLogger(), mock_mint_fetcher, mock_blockchain_context, protocol_mint_data)
    payload = {
        'op': 'deploy',
        'p': 'ppp',
        'args': {
        }
    }
    atomicals_spent_at_inputs = {}
    request_tx_context = RequestTxContext(coin, mock_tx_hash2, mock_tx2, payload, b'')

    deploy_command = avm.create_deploy_command(request_tx_context, atomicals_spent_at_inputs, mock_empty_reactor_context)
    assert(deploy_command.is_valid)
    assert(deploy_command.unlock_script.hex() == '')
    assert(deploy_command.lock_script.hex() == '51cc0087')

    result = deploy_command.execute() 
    assert result.success  