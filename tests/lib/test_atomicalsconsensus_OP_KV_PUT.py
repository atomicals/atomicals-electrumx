import pytest

from electrumx.lib.coins import Bitcoin
from electrumx.lib.hash import hex_str_to_hash

from electrumx.lib.avm.util import (
    encode_int_value,
    RequestInterpretParams,
    RequestBlockchainContext,
    print_result_states,
    ReactorContext,
    RequestTxContext,
    ScriptContext
)  
from bitcointx.core.atomicalsconsensus import (
  ConsensusVerifyScriptAvmExecute,
  AtomicalConsensusExecutionError
)
from bitcointx.core.script import (
  CScript
)

from cbor2 import dumps, loads, CBORDecodeError

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
mock_empty_reactor_context = ReactorContext(None, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  
def test_atomicalsconsensus_OP_KV_PUT_1():
  #with pytest.raises(AtomicalConsensusExecutionError) as exc: 
    payload = {}  
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
    state_hash = bytes.fromhex('00000000000000000000000000000000000000000000000000000000000000')
    reactor_context = ReactorContext(state_hash, dumps({
      "02": {
        "00": "68656c6c6f"
      }
    }), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
    blockchain_context = RequestBlockchainContext(mock_headers, 840012)
    script_context = ScriptContext(CScript(), CScript(bytes.fromhex('520100026f6ff0520100ef026f6f87')))
    result_context = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
    assert result_context
    assert loads(result_context.state) == {'02': {'00': '6f6f'}}
    state = loads(result_context.state)
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
    
    assert result_context.state_hash.hex() == '26305552867599df1f263483988df47c05af348a0475421fe498ff2fdb1af08f'
    assert loads(result_context.state_updates) == {'02': {'00': '6f6f'}}
    assert loads(result_context.state_deletes) == {}
    assert len(state) == 1
    assert len(state_updates) == 1 
    assert len(state_deletes) == 0 
    assert len(ft_incoming) == 0 
    assert len(nft_incoming) == 0 
    assert len(ft_balances) == 0 
    assert len(ft_balances_updates) == 0 
    assert len(nft_balances) == 0 
    assert len(nft_balances_updates) == 0 
    assert len(ft_withdraws) == 0 
    assert len(nft_withdraws) == 0 

def test_atomicalsconsensus_OP_KV_PUT_2():
  payload = {}  
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  reactor_context = ReactorContext(state_hash, dumps({
    "02": {
      "00": "68656c6c6f"
    }
  }), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex('02123451026f6df051')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert loads(updated_reactor_state.state) == {
      '1234': {
        '01': '6f6d'
      },
      "02": {
        "00": "68656c6c6f"
      }
  }
  state = loads(updated_reactor_state.state)
  ft_incoming = loads(updated_reactor_state.ft_incoming)
  nft_incoming = loads(updated_reactor_state.nft_incoming)
  ft_balances = loads(updated_reactor_state.ft_balances)
  nft_balances = loads(updated_reactor_state.nft_balances)
  ft_withdraws = loads(updated_reactor_state.ft_withdraws)
  nft_withdraws = loads(updated_reactor_state.nft_withdraws)
  
  assert updated_reactor_state.state_hash.hex() == '1c014b91b88083c4231abbd74923d24fa39e7d4e6487fb54d0ef972b5fa1b4ac'
  assert len(state) == 2
  assert len(ft_incoming) == 0 
  assert len(nft_incoming) == 0 
  assert len(ft_balances) == 0 
  assert len(nft_balances) == 0 
  assert len(ft_withdraws) == 0 
  assert len(nft_withdraws) == 0 
 
def test_atomicalsconsensus_OP_KV_PUT_3():
  with pytest.raises(AtomicalConsensusExecutionError) as exc: 
    payload = {}  
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
    state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    reactor_context = ReactorContext(state_hash, dumps({
      "02": {
        "00": "68656c6c6f"
      }
    }), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
    blockchain_context = RequestBlockchainContext(mock_headers, 840012)
    script_context = ScriptContext(CScript(), CScript(bytes.fromhex('5404123456780488887777767e767e767e767e767e767e767e767e767e767e767e767e767ef051')))
    ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert exc.value.error_code == 0
  assert exc.value.script_error == 5
  assert exc.value.script_error_op_num == 22
       