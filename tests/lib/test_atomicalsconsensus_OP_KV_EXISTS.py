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

def test_atomicalsconsensus_OP_KV_EXISTS_1():
  payload = {}  
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  reactor_context = ReactorContext(state_hash, dumps({
    '00': {
      "012345": "68656c6c6f"
    }
  }), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex('010003012345ed')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  state = loads(updated_reactor_state.state)
  assert state['00']
  assert state['00']['012345'] == '68656c6c6f'
  assert updated_reactor_state.state == dumps({
    '00': {
      "012345": "68656c6c6f"
    }
  })
  assert loads(updated_reactor_state.state_updates) == {
  }

def test_atomicalsconsensus_OP_KV_EXISTS_2_not_found():
  payload = {}  
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  reactor_context = ReactorContext(state_hash, dumps({
    '00': {
      "012345": "68656c6c6f"
    }
  }), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex('018803012345ed0087')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  state = loads(updated_reactor_state.state)
  assert state['00']
  assert state['00']['012345'] == '68656c6c6f'
  assert updated_reactor_state.state == dumps({
    '00': {
      "012345": "68656c6c6f"
    }
  })
  assert loads(updated_reactor_state.state_updates) == {}

def test_atomicalsconsensus_OP_KV_EXISTS_3():
  with pytest.raises(AtomicalConsensusExecutionError) as exc: 
    payload = {}  
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
    state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    reactor_context = ReactorContext(state_hash, dumps({
      '00': {
        "012345": "68656c6c6f"
      }
    }), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
    blockchain_context = RequestBlockchainContext(mock_headers, 840012)
    script_context = ScriptContext(CScript(), CScript(bytes.fromhex('010003012346ed')))
    updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert exc.value.error_code == 0
  assert exc.value.script_error == 2
  assert exc.value.script_error_op_num == 2

def test_atomicalsconsensus_OP_KV_EXISTS_4():
  with pytest.raises(AtomicalConsensusExecutionError) as exc: 
    payload = {}  
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
    state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    reactor_context = ReactorContext(state_hash, dumps({
      '00': {
        "012345": "68656c6c6f"
      }
    }), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
    blockchain_context = RequestBlockchainContext(mock_headers, 840012)
    script_context = ScriptContext(CScript(), CScript(bytes.fromhex('015503012345ed')))
    updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert exc.value.error_code == 0
  assert exc.value.script_error == 2
  assert exc.value.script_error_op_num == 2
 