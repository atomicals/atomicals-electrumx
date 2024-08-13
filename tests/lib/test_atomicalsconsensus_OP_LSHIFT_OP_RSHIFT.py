import pytest

from electrumx.lib.coins import Bitcoin
from electrumx.lib.hash import hex_str_to_hash

from electrumx.lib.avm.util import (
    encode_int_value,
    RequestInterpretParams,
    RequestBlockchainContext,
    print_result_states,
    ScriptContext,
    encode_op_pushdata
)
 
from electrumx.lib.avm.avm import (
    RequestBlockchainContext,
    RequestTxContext,
    ReactorContext
)
from bitcointx.core.atomicalsconsensus import (
  ConsensusVerifyScriptAvmExecute,
  AtomicalConsensusExecutionError
)

from bitcointx.core.script import (
  CScript
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

mock_current_header = '000000209174c9f2757e2647733c9ab69c133b90257f85ce7e9c0100000000000000000096e490f16d161416bef825bd4716b0914f344be5835cf6a8f0de89288a6c440391af0566d3620317aca8414a'
mock_headers = {
    '840012': mock_current_header
}
mock_blockchain_context = RequestBlockchainContext(mock_headers, 840012)
mock_rawtx = bytes.fromhex('02000000018e469f953413e8d865fcf1f47d759772aa05e8d78b1e4577a58edc8bd09344ff010000006b483045022100ce16646785907c919a1658496a85cf3f3d877d98ffca5eabd189524acc1de53b02205ac24a9e2855db3da26b840c82fddaf73a5a6eff4b5b78cadfb00584ad6bd5f3012102cbcad7b21fb5fb08ad55eb09e327b97f63e8c5e99b2faf9bb330545a5bd4602cfeffffff0203761700000000001976a91496d02c013f734a642871261324c58091a806c23188ac9ce52300000000001976a914a9a8d5aa3ec73688d0540d45be3842f4603705c588ac6e640800')
mock_tx, mock_tx_hash = coin.DESERIALIZER(mock_rawtx, 0).read_tx_and_hash()
mock_empty_reactor_context = ReactorContext(None, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
 
def test_atomicalsconsensus_OP_LSHIFT_insufficient_stack():
  with pytest.raises(AtomicalConsensusExecutionError) as exc: 
    payload = {}  
    state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
    reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
    blockchain_context = RequestBlockchainContext(mock_headers, 840012)
    script_context = ScriptContext(CScript(), CScript(bytes.fromhex('0098')))
    updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
    assert updated_reactor_state
  assert exc.value.error_code == 0
  assert exc.value.script_error == 24
  assert exc.value.script_error_op_num == 1
 
def test_atomicalsconsensus_OP_RSHIFT_insufficient_stack():
  with pytest.raises(AtomicalConsensusExecutionError) as exc: 
    payload = {}  
    state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
    reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
    blockchain_context = RequestBlockchainContext(mock_headers, 840012)
    script_context = ScriptContext(CScript(), CScript(bytes.fromhex('0099')))
    updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
    assert updated_reactor_state
  assert exc.value.error_code == 0
  assert exc.value.script_error == 24
  assert exc.value.script_error_op_num == 1

def test_atomicalsconsensus_OP_LSHIFT_zero_success():
  payload = {}  
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex('0000980087')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert updated_reactor_state
  
def test_atomicalsconsensus_OP_RSHIFT_zero_success():
  payload = {}  
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex('0000990087')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert updated_reactor_state

def test_atomicalsconsensus_OP_LSHIFT_1_shift_zero_success():
  payload = {}  
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex('0051980087')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert updated_reactor_state

def test_atomicalsconsensus_OP_RSHIFT_1_shift_zero_success():
  payload = {}  
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex('0051990087')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert updated_reactor_state

def test_atomicalsconsensus_OP_LSHIFT_minus_1_shift_zero_fail():
  with pytest.raises(AtomicalConsensusExecutionError) as exc: 
    payload = {}  
    state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
    reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
    blockchain_context = RequestBlockchainContext(mock_headers, 840012)
    script_context = ScriptContext(CScript(), CScript(bytes.fromhex('00518f980087')))
    ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert exc.value.error_code == 0
  assert exc.value.script_error == 12
  assert exc.value.script_error_op_num == 3

def test_atomicalsconsensus_OP_RSHIFT_minus_1_shift_zero_fail():
  with pytest.raises(AtomicalConsensusExecutionError) as exc: 
    payload = {}  
    state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
    reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
    blockchain_context = RequestBlockchainContext(mock_headers, 840012)
    script_context = ScriptContext(CScript(), CScript(bytes.fromhex('00518f990087')))
    ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert exc.value.error_code == 0
  assert exc.value.script_error == 12
  assert exc.value.script_error_op_num == 3

def test_atomicalsconsensus_OP_LSHIFT_1_shift_32_success():
  payload = {}  
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex('01205198014087')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert updated_reactor_state

def test_atomicalsconsensus_OP_LSHIFT_loop_shift_success():
  payload = {}  
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  max_int = 9223372036854775807
  test_items = [
     {
        'num': 0,
        'shift': 1,
        'result': '00'
     },
     {
        'num': 1,
        'shift': 1,
        'result': '52'
     },
     {
        'num': 2,
        'shift': 1,
        'result': '54'
     },
     {
        'num': 4,
        'shift': 1,
        'result': '58'
     },
     {
        'num': 8,
        'shift': 2,
        'result': '0120'
     },
     {
        'num': 1024,
        'shift': 1,
        'result': '020008'
     },
     {
        'num': 1024,
        'shift': 2,
        'result': '020010'
     },
     {
        'num': 1024,
        'shift': 3,
        'result': '020020'
     },
     {
        'num': 1024,
        'shift': 4,
        'result': '020040'
     },
     {
        'num': 1024,
        'shift': 5,
        'result': '020080'
     },
     {
        'num': 1024,
        'shift': 6,
        'result': '020100'
     },
    {
        'num': max_int,
        'shift': 1,
        'result': '08fffffffffffffefe'
     } 
  ]
 
  for item in test_items:
    num_enc = encode_int_value(item['num'], True)
    shift_enc = encode_int_value(item['shift'], True)
    script_context = ScriptContext(CScript(), CScript(bytes.fromhex(num_enc + shift_enc + '98' + item['result'] + '87')))
    updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
    assert updated_reactor_state
     
def test_atomicalsconsensus_OP_RSHIFT_1_shift_32_success():
  payload = {}  
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex('012051996087')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert updated_reactor_state


def test_atomicalsconsensus_OP_RSHIFT_loop_shift_success():
  payload = {}  
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)

  max_int = 9223372036854775807
  test_items = [
     {
        'num': 0,
        'shift': 1,
        'result': '00'
     },
     {
        'num': 1,
        'shift': 1,
        'result': '00'
     },
     {
        'num': 2,
        'shift': 1,
        'result': '51'
     },
     {
        'num': 4,
        'shift': 1,
        'result': '52'
     },
     {
        'num': 8,
        'shift': 2,
        'result': '52'
     },
     {
        'num': 1024,
        'shift': 1,
        'result': '020002'
     },
     {
        'num': 1024,
        'shift': 2,
        'result': '020001'
     },
     {
        'num': 1024,
        'shift': 3,
        'result': '00'
     },
     {
        'num': 1024,
        'shift': 4,
        'result': '00'
     },
     {
        'num': max_int,
        'shift': 1,
        'result': '087fffffffffffffbf'
     } 

  ]
 
  for item in test_items:
    num_enc = encode_int_value(item['num'], True)
    shift_enc = encode_int_value(item['shift'], True)
    script_context = ScriptContext(CScript(), CScript(bytes.fromhex(num_enc + shift_enc + '9981' + item['result'] + '87')))
    updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
    assert updated_reactor_state