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
mock_rawtx = bytes.fromhex('02000000018e469f953413e8d865fcf1f47d759772aa05e8d78b1e4577a58edc8bd09344ff010000006b483045022100ce16646785907c919a1658496a85cf3f3d877d98ffca5eabd189524acc1de53b02205ac24a9e2855db3da26b840c82fddaf73a5a6eff4b5b78cadfb00584ad6bd5f3012102cbcad7b21fb5fb08ad55eb09e327b97f63e8c5e99b2faf9bb330545a5bd4602cfeffffff0203761700000000001976a91496d02c013f734a642871261324c58091a806c23188ac9ce52300000000001976a914a9a8d5aa3ec73688d0540d45be3842f4603705c588ac6e640800')
mock_tx, mock_tx_hash = coin.DESERIALIZER(mock_rawtx, 0).read_tx_and_hash()
mock_empty_reactor_context = ReactorContext(None,  dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))

def test_prepare_deploy_script():
    # Todo expand on various cases for deploy script creation
    assert(True)

def test_execute_deploy_script1():
    protocol_mint_data = {
        'p': 'ppp',
        'code': bytes.fromhex('5187'),
        'fn': [
            {
                'name': 'ctor',
                'params': [
                    {
                        'name': 'age',
                        'type': 'int'
                    } 
                ]
            }
        ]
    }
    avm = AVMFactory(MockLogger(), mock_mint_fetcher, mock_blockchain_context, protocol_mint_data)
    payload = {
        'op': 'deploy',
        'p': 'ppp',
        'args': {
            'age': 1
        }
    }
    atomicals_spent_at_inputs = {}
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)

    deploy_command = avm.create_deploy_command(request_tx_context, atomicals_spent_at_inputs, mock_empty_reactor_context)
    assert(deploy_command.is_valid)
    assert(deploy_command.unlock_script.hex() == '51')
    assert(deploy_command.lock_script.hex() == '5187')

    result = deploy_command.execute() 
    assert result.success 
    assert result.reactor_context

    result_context = result.reactor_context
    state_hash = result_context.state_hash
    state = loads(result_context.state)
    state_updates = loads(result_context.state_updates)
    state_deletes = loads(result_context.state_deletes)
    ft_incoming = loads(result_context.ft_incoming)
    nft_incoming = loads(result_context.nft_incoming)
    ft_balances = loads(result_context.ft_balances)
    ft_balances_updates = loads(result_context.ft_balances_updates)
    nft_balances = loads(result_context.nft_balances)
    nft_balances_updates = loads(result_context.nft_balances_updates)
    ft_withdraws = loads(result_context.ft_withdraws)
    nft_withdraws = loads(result_context.nft_withdraws)
    
    assert state_hash.hex() == '71daaf262004b5778dfb085daf074cf22a9e4c6f60eb8700974ba6bd3cc2b156'
    assert len(state) == 0 
    assert len(state_updates) == 0 
    assert len(state_deletes) == 0 
    assert len(ft_incoming) == 0 
    assert len(nft_incoming) == 0 
    assert len(ft_balances) == 0 
    assert len(ft_balances_updates) == 0 
    assert len(nft_balances) == 0 
    assert len(nft_balances_updates) == 0 
    assert len(ft_withdraws) == 0 
    assert len(nft_withdraws) == 0 

 