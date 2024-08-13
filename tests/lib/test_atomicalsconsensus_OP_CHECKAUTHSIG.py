
import pytest

from electrumx.lib.coins import Bitcoin
from electrumx.lib.hash import hex_str_to_hash

from electrumx.lib.avm.avm import (
    AVMFactory,
    RequestBlockchainContext,
    RequestTxContext,
    ReactorContext,
    ScriptContext
)
from bitcointx.core.script import (
  CScript
)
from bitcointx.core.atomicalsconsensus import (
  ConsensusVerifyScriptAvmExecute,
  AtomicalConsensusExecutionError
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

def test_execute_OP_CHECKAUTHSIG_with_valid_sig():
    rawtx_with_valid_sig = bytes.fromhex('01000000000101968502233a8ee5710490e98249727d618acf53dee6f078a4dc399363083c6ba70000000000ffffffff022202000000000000225120478a6ceb2d7bf2f88b0b644ba6c8b11b583722afca033dc8ea1c259cac50580200000000000000004c6a03736967463044022030b22811681b84763e3ecb9e5a4bc78344c48226c9f20e36192c46e39e294bb80220474d5b000eebe5ab48df53e12dfbc349b8fd4ac21d6e3839a873f0820f946a6c0340e0afc071d8c1ef4fbe56ee66b3a236d9195c95dfd778e1b8238d6e18498cd522460d444688d1339efe1bd24cbc97db42903f52e3c3b1cd0c8b3c620384a4c34c83209f76f4e90e426cae195e7092cf8ec81d3005a90574e6d0532c679983ad79d7eaac00630461746f6d01634c55a4616e63683431617541516461726773a36474696d651a66ae5292656e6f6e63650068626974776f726b63616164617574685821025388218c5ecdc718f49b7788306425f8577c88cacbaf48a2962a804bb64c6ec96821c19f76f4e90e426cae195e7092cf8ec81d3005a90574e6d0532c679983ad79d7ea00000000')
    tx_with_valid_sig, tx_with_valid_sig_txid = coin.DESERIALIZER(rawtx_with_valid_sig, 0).read_tx_and_hash()
    payload = {
        'auth': bytes.fromhex('025388218c5ecdc718f49b7788306425f8577c88cacbaf48a2962a804bb64c6ec9')
    }  
    request_tx_context = RequestTxContext(coin, tx_with_valid_sig_txid, tx_with_valid_sig, payload)
    state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    reactor_context = ReactorContext(state_hash, dumps({
        '00': {
            '0123': '4321'
        }
    }), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
    blockchain_context = RequestBlockchainContext(mock_headers, 840012)
    script_context = ScriptContext(CScript(bytes.fromhex('51')), CScript(bytes.fromhex('51876351036d7367c10768656c6c6f2c207ef06851')))
    updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
    print(f'{loads(updated_reactor_state.state)}')
    assert loads(updated_reactor_state.state) == {
        '00': {
            '0123': '4321'
        },
        '01': {
            '6d7367': '025388218c5ecdc718f49b7788306425f8577c88cacbaf48a2962a804bb64c6ec968656c6c6f2c20'
        }
    }
    state = loads(updated_reactor_state.state)
    ft_incoming = loads(updated_reactor_state.ft_incoming)
    nft_incoming = loads(updated_reactor_state.nft_incoming)
    ft_balances = loads(updated_reactor_state.ft_balances)
    nft_balances = loads(updated_reactor_state.nft_balances)
    ft_withdraws = loads(updated_reactor_state.ft_withdraws)
    nft_withdraws = loads(updated_reactor_state.nft_withdraws)
    print(updated_reactor_state.state_hash.hex())
    assert updated_reactor_state.state_hash.hex() == 'e21b49dd4f89d022b59df656045a62112ca35dcb68fc22b0eeee111090523f5d'
    assert len(state) == 2
    assert len(ft_incoming) == 0 
    assert len(nft_incoming) == 0 
    assert len(ft_balances) == 0 
    assert len(nft_balances) == 0 
    assert len(ft_withdraws) == 0 
    assert len(nft_withdraws) == 0 

def test_execute_OP_CHECKAUTHSIG_with_invalid_pubkey_sig():
    with pytest.raises(AtomicalConsensusExecutionError) as exc: 
        rawtx_with_valid_sig = bytes.fromhex('01000000000101968502233a8ee5710490e98249727d618acf53dee6f078a4dc399363083c6ba70000000000ffffffff022202000000000000225120478a6ceb2d7bf2f88b0b644ba6c8b11b583722afca033dc8ea1c259cac50580200000000000000004c6a03736967463044022030b22811681b84763e3ecb9e5a4bc78344c48226c9f20e36192c46e39e294bb80220474d5b000eebe5ab48df53e12dfbc349b8fd4ac21d6e3839a873f0820f946a6c0340e0afc071d8c1ef4fbe56ee66b3a236d9195c95dfd778e1b8238d6e18498cd522460d444688d1339efe1bd24cbc97db42903f52e3c3b1cd0c8b3c620384a4c34c83209f76f4e90e426cae195e7092cf8ec81d3005a90574e6d0532c679983ad79d7eaac00630461746f6d01634c55a4616e63683431617541516461726773a36474696d651a66ae5292656e6f6e63650068626974776f726b63616164617574685821025388218c5ecdc718f49b7788306425f8577c88cacbaf48a2962a804bb64c6ec96821c19f76f4e90e426cae195e7092cf8ec81d3005a90574e6d0532c679983ad79d7ea00000000')
        tx_with_valid_sig, tx_with_valid_sig_txid = coin.DESERIALIZER(rawtx_with_valid_sig, 0).read_tx_and_hash()
        payload = {
            'auth': bytes.fromhex('025388218c5ecdc718f49b7788306425f8577c88cacbaf48a2962a804bb64c6ec8')
        }  
        request_tx_context = RequestTxContext(coin, tx_with_valid_sig_txid, tx_with_valid_sig, payload)
        state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
        reactor_context = ReactorContext(state_hash, dumps({
            '00': {
                '0123': '4321'
            }
        }), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
        blockchain_context = RequestBlockchainContext(mock_headers, 840012)
        script_context = ScriptContext(CScript(bytes.fromhex('51')), CScript(bytes.fromhex('51876351036d7367c10768656c6c6f2c207ef06851')))
        updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
                
    assert exc.value.error_code == 0
    assert exc.value.script_error == 89
    assert exc.value.script_error_op_num == 5