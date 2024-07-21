import pytest

from electrumx.lib.coins import Bitcoin
from electrumx.lib.hash import hex_str_to_hash

from electrumx.lib.avm.util import (
    encode_int_value,
    RequestInterpretParams,
    RequestBlockchainContext,
    print_result_states,
    encode_op_pushdata,
    RequestTxContext,
    ReactorContext,
    ScriptContext
)
from electrumx.lib.avm.avm import (
    AVMFactory
)
from electrumx.lib.util_atomicals import (
    location_id_bytes_to_compact
)

import bitcointx
import re
from electrumx.lib.util import (
  pack_le_uint64,
  pack_le_uint32
)
import struct
 
from bitcointx.core.atomicalsconsensus import (
  ConsensusVerifyScriptAvmExecute,
  AtomicalConsensusExecutionError
)

from bitcointx.core.script import (
  CScript, CScriptOp, OP_1NEGATE
)
from bitcointx.core._bignum import (
  bn2vch
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
  
mock_current_header = '000000209174c9f2757e2647733c9ab69c133b90257f85ce7e9c0100000000000000000096e490f16d161416bef825bd4716b0914f344be5835cf6a8f0de89288a6c440391af0566d3620317aca8414a'
mock_headers = {
    '840012': mock_current_header
}
mock_blockchain_context = RequestBlockchainContext(mock_headers, 840012)
mock_rawtx = bytes.fromhex('02000000018e469f953413e8d865fcf1f47d759772aa05e8d78b1e4577a58edc8bd09344ff010000006b483045022100ce16646785907c919a1658496a85cf3f3d877d98ffca5eabd189524acc1de53b02205ac24a9e2855db3da26b840c82fddaf73a5a6eff4b5b78cadfb00584ad6bd5f3012102cbcad7b21fb5fb08ad55eb09e327b97f63e8c5e99b2faf9bb330545a5bd4602cfeffffff0203761700000000001976a91496d02c013f734a642871261324c58091a806c23188ac9ce52300000000001976a914a9a8d5aa3ec73688d0540d45be3842f4603705c588ac6e640800')
mock_tx, mock_tx_hash = coin.DESERIALIZER(mock_rawtx, 0).read_tx_and_hash()
mock_empty_reactor_context = ReactorContext(None, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))

def test_atomicalsconsensus_OP_FT_WITHDRAW_invalid_amount_for_no_id():
  with pytest.raises(AtomicalConsensusExecutionError) as exc: 
    payload = {}  
    balances = {}
    sample_token_id1 = '012345678901234567890123456789012345678901234567890123456789000000000000'
    sample_token_id1_bytes = bytearray.fromhex(sample_token_id1)
    sample_token_id1_bytes.reverse()
    sample_token_id1_encoded = encode_op_pushdata(sample_token_id1_bytes)
    sample_token_id2 = '712345678901234567890123456789012345678901234567890123456789000000000002'
    sample_token_id2_bytes = bytearray.fromhex(sample_token_id2)
    sample_token_id2_bytes.reverse()
    sample_token_id2_encoded = encode_op_pushdata(sample_token_id2_bytes)
    balances[sample_token_id1] = 1
    state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
    reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps(balances), dumps({}), dumps({}), dumps({}))
    blockchain_context = RequestBlockchainContext(mock_headers, 840012)
    script_context = ScriptContext(CScript(), CScript(bytes.fromhex(sample_token_id2_encoded.hex() + '0051f2')))
    updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
    assert updated_reactor_state
  assert exc.value.error_code == 0
  assert exc.value.script_error == 63
  assert exc.value.script_error_op_num == 3
 
def test_atomicalsconsensus_OP_FT_WITHDRAW_invalid_output_index():
  with pytest.raises(AtomicalConsensusExecutionError) as exc: 
    payload = {}  
    balances = {}
    sample_token_id1 = '012345678901234567890123456789012345678901234567890123456789000000000000'
    sample_token_id1_bytes = bytearray.fromhex(sample_token_id1)
    sample_token_id1_bytes.reverse()
    sample_token_id1_encoded = encode_op_pushdata(sample_token_id1_bytes)
    sample_token_id2 = '712345678901234567890123456789012345678901234567890123456789000000000002'
    sample_token_id2_bytes = bytearray.fromhex(sample_token_id2)
    sample_token_id2_bytes.reverse()
    sample_token_id2_encoded = encode_op_pushdata(sample_token_id2_bytes)
    balances[sample_token_id1] = 1
    state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
    reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps(balances), dumps({}), dumps({}), dumps({}))
    blockchain_context = RequestBlockchainContext(mock_headers, 840012)
    script_context = ScriptContext(CScript(), CScript(bytes.fromhex(sample_token_id2_encoded.hex() + '5851f2')))
    updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
    assert updated_reactor_state
  assert exc.value.error_code == 0
  assert exc.value.script_error == 64
  assert exc.value.script_error_op_num == 3

def test_atomicalsconsensus_OP_FT_WITHDRAW_invalid_amount_for_amount_0():
  with pytest.raises(AtomicalConsensusExecutionError) as exc: 
    payload = {}  
    balances = {}
    sample_token_id1 = '012345678901234567890123456789012345678901234567890123456789000000000000'
    sample_token_id1_bytes = bytearray.fromhex(sample_token_id1)
    sample_token_id1_bytes.reverse()
    sample_token_id1_encoded = encode_op_pushdata(sample_token_id1_bytes)
    sample_token_id2 = '712345678901234567890123456789012345678901234567890123456789000000000002'
    sample_token_id2_bytes = bytearray.fromhex(sample_token_id2)
    sample_token_id2_bytes.reverse()
    sample_token_id2_encoded = encode_op_pushdata(sample_token_id2_bytes)
    balances[sample_token_id1] = 1
    too_big_amount = encode_int_value(999999999)
    state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
    reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps(balances), dumps({}), dumps({}), dumps({}))
    blockchain_context = RequestBlockchainContext(mock_headers, 840012)
    script_context = ScriptContext(CScript(), CScript(bytes.fromhex(sample_token_id1_encoded.hex() + '00' + too_big_amount.hex() + 'f2')))
    updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
    assert updated_reactor_state
  assert exc.value.error_code == 0
  assert exc.value.script_error == 62
  assert exc.value.script_error_op_num == 3

def test_atomicalsconsensus_OP_FT_WITHDRAW_no_balance_available_single_output():
  with pytest.raises(AtomicalConsensusExecutionError) as exc: 
    payload = {}  
    balances = {}
    sample_token_id1 = '012345678901234567890123456789012345678901234567890123456789000000000000'
    sample_token_id1_bytes = bytearray.fromhex(sample_token_id1)
    sample_token_id1_bytes.reverse()
    sample_token_id1_encoded = encode_op_pushdata(sample_token_id1_bytes)
    sample_token_id2 = '712345678901234567890123456789012345678901234567890123456789000000000002'
    sample_token_id2_bytes = bytearray.fromhex(sample_token_id2)
    sample_token_id2_bytes.reverse()
    sample_token_id2_encoded = encode_op_pushdata(sample_token_id2_bytes)
    balances[sample_token_id1] = 2
    balances[sample_token_id2] = 3
    state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
    reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps(balances), dumps({}), dumps({}), dumps({}))
    blockchain_context = RequestBlockchainContext(mock_headers, 840012)
    script_context = ScriptContext(CScript(), CScript(bytes.fromhex(sample_token_id1_encoded.hex() + '00' + '53' + 'f2')))
    updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
    assert updated_reactor_state
  assert exc.value.error_code == 0
  assert exc.value.script_error == 63
  assert exc.value.script_error_op_num == 3

def test_atomicalsconsensus_OP_FT_WITHDRAW_no_balance_available_multiple_outputs():
  with pytest.raises(AtomicalConsensusExecutionError) as exc: 
    payload = {}  
    balances = {}
    sample_token_id1 = '012345678901234567890123456789012345678901234567890123456789000000000000'
    sample_token_id1_bytes = bytearray.fromhex(sample_token_id1)
    sample_token_id1_bytes.reverse()
    sample_token_id1_encoded = encode_op_pushdata(sample_token_id1_bytes)
    sample_token_id2 = '712345678901234567890123456789012345678901234567890123456789000000000002'
    sample_token_id2_bytes = bytearray.fromhex(sample_token_id2)
    sample_token_id2_bytes.reverse()
    sample_token_id2_encoded = encode_op_pushdata(sample_token_id2_bytes)
    balances[sample_token_id1] = 2
    balances[sample_token_id2] = 3
    state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
    reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps(balances), dumps({}), dumps({}), dumps({}))
    blockchain_context = RequestBlockchainContext(mock_headers, 840012)
    script_context = ScriptContext(CScript(), CScript(bytes.fromhex(sample_token_id1_encoded.hex() + '00' + '51' + 'f2' + sample_token_id1_encoded.hex() + '51' + '52' + 'f2')))
    updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
    assert updated_reactor_state
  assert exc.value.error_code == 0
  assert exc.value.script_error == 63
  assert exc.value.script_error_op_num == 7

def test_atomicalsconsensus_OP_FT_WITHDRAW_adequate_balance_available_single_output():
  payload = {}  
  balances = {}
  sample_token_id1 = '012345678901234567890123456789012345678901234567890123456789000000000000'
  sample_token_id1_bytes = bytearray.fromhex(sample_token_id1)
  sample_token_id1_bytes.reverse()
  sample_token_id1_encoded = encode_op_pushdata(sample_token_id1_bytes)
  sample_token_id2 = '712345678901234567890123456789012345678901234567890123456789000000000002'
  sample_token_id2_bytes = bytearray.fromhex(sample_token_id2)
  sample_token_id2_bytes.reverse()
  sample_token_id2_encoded = encode_op_pushdata(sample_token_id2_bytes)
  balances[sample_token_id1] = 2
  balances[sample_token_id2] = 3
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps(balances), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex(sample_token_id1_encoded.hex() + '00' + '52' + 'f251')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert updated_reactor_state
  expected_balances = {}
  # expected_balances[sample_token_id1] = 0
  expected_balances[sample_token_id2] = 3
  assert updated_reactor_state.ft_balances == dumps(expected_balances)
  print(loads(updated_reactor_state.state))
  assert len(loads(updated_reactor_state.state)) == 0 
  assert len(loads(updated_reactor_state.state_updates)) == 0 
  assert len(loads(updated_reactor_state.state_deletes)) == 0 
  assert len(loads(updated_reactor_state.ft_incoming)) == 0
  assert len(loads(updated_reactor_state.nft_incoming)) == 0 
  assert len(loads(updated_reactor_state.ft_balances)) == 1
  expected_balances_updates = {}
  expected_balances_updates[sample_token_id1] = 0
  assert updated_reactor_state.ft_balances_updates == dumps(expected_balances_updates)
  assert len(loads(updated_reactor_state.ft_balances_updates)) == 1
  assert len(loads(updated_reactor_state.nft_balances)) == 0 
  assert len(loads(updated_reactor_state.nft_balances_updates)) == 0 
  expected_ft_withdraws = {}
  expected_ft_withdraws[sample_token_id1] =  {
    '0': 2
  }
  print(loads(updated_reactor_state.ft_withdraws))
  assert updated_reactor_state.ft_withdraws == dumps(expected_ft_withdraws)
  assert len(loads(updated_reactor_state.ft_withdraws)) == 1
  assert len(loads(updated_reactor_state.nft_withdraws)) == 0 

def test_atomicalsconsensus_OP_FT_WITHDRAW_incoming_adequate_balance_multiple_output():
  payload = {}  
  balances = {}
  sample_token_id1 = '012345678901234567890123456789012345678901234567890123456789000000000000'
  sample_token_id1_bytes = bytearray.fromhex(sample_token_id1)
  sample_token_id1_bytes.reverse()
  sample_token_id1_encoded = encode_op_pushdata(sample_token_id1_bytes)
  sample_token_id2 = '712345678901234567890123456789012345678901234567890123456789000000000002'
  sample_token_id2_bytes = bytearray.fromhex(sample_token_id2)
  sample_token_id2_bytes.reverse()
  sample_token_id2_encoded = encode_op_pushdata(sample_token_id2_bytes)
  balances[sample_token_id1] = 2
  balances[sample_token_id2] = 3
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps(balances), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex(sample_token_id1_encoded.hex() + '00' + '51' + 'f2' + sample_token_id1_encoded.hex() + '51' + '51' + 'f2' + '51')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert updated_reactor_state
  expected_balances = {}
  # expected_balances[sample_token_id1] = 0
  expected_balances[sample_token_id2] = 3
  assert updated_reactor_state.ft_balances == dumps(expected_balances)
  print(loads(updated_reactor_state.state))
  assert len(loads(updated_reactor_state.state)) == 0 
  assert len(loads(updated_reactor_state.state_updates)) == 0 
  assert len(loads(updated_reactor_state.state_deletes)) == 0 
  assert len(loads(updated_reactor_state.ft_incoming)) == 0
  assert len(loads(updated_reactor_state.nft_incoming)) == 0 
  assert len(loads(updated_reactor_state.ft_balances)) == 1
  expected_balances_updates = {}
  expected_balances_updates[sample_token_id1] = 0
  assert updated_reactor_state.ft_balances_updates == dumps(expected_balances_updates)
  assert len(loads(updated_reactor_state.ft_balances_updates)) == 1
  assert len(loads(updated_reactor_state.nft_balances)) == 0 
  assert len(loads(updated_reactor_state.nft_balances_updates)) == 0 
  expected_ft_withdraws = {}
  expected_ft_withdraws[sample_token_id1] =  {
    '0': 1,
    '1': 1
  }
  print(loads(updated_reactor_state.ft_withdraws))
  assert updated_reactor_state.ft_withdraws == dumps(expected_ft_withdraws)
  assert len(loads(updated_reactor_state.ft_withdraws)) == 1
  assert len(loads(updated_reactor_state.nft_withdraws)) == 0 


def test_atomicalsconsensus_OP_FT_WITHDRAW_incoming_added_balance_multiple_output():
  payload = {}  
  balances = {}
  balances_incoming = {}
  sample_token_id1 = '012345678901234567890123456789012345678901234567890123456789000000000000'
  sample_token_id1_bytes = bytearray.fromhex(sample_token_id1)
  sample_token_id1_bytes.reverse()
  sample_token_id1_encoded = encode_op_pushdata(sample_token_id1_bytes)
  sample_token_id2 = '712345678901234567890123456789012345678901234567890123456789000000000002'
  sample_token_id2_bytes = bytearray.fromhex(sample_token_id2)
  sample_token_id2_bytes.reverse()
  sample_token_id2_encoded = encode_op_pushdata(sample_token_id2_bytes)
  balances[sample_token_id1] = 2
  balances[sample_token_id2] = 3
  balances_incoming[sample_token_id1] = 3
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps(balances_incoming), dumps({}), dumps({}), dumps(balances), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex(sample_token_id1_encoded.hex() + 'd3' + sample_token_id1_encoded.hex() + '00' + '53' + 'f2' + sample_token_id1_encoded.hex() + '51' + '52' + 'f2' + '51')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  expected_balances = {}
  expected_balances[sample_token_id2] = 3
  assert updated_reactor_state.ft_balances == dumps(expected_balances)
  assert len(loads(updated_reactor_state.state)) == 0 
  assert len(loads(updated_reactor_state.state_updates)) == 0 
  assert len(loads(updated_reactor_state.state_deletes)) == 0 
  assert len(loads(updated_reactor_state.ft_incoming)) == 1
  assert len(loads(updated_reactor_state.nft_incoming)) == 0 
  assert len(loads(updated_reactor_state.ft_balances)) == 1
  expected_balances_updates = {}
  expected_balances_updates[sample_token_id1] = 0
  assert updated_reactor_state.ft_balances_updates == dumps(expected_balances_updates)
  assert len(loads(updated_reactor_state.ft_balances_updates)) == 1
  assert len(loads(updated_reactor_state.nft_balances)) == 0 
  assert len(loads(updated_reactor_state.nft_balances_updates)) == 0 
  expected_ft_withdraws = {}
  expected_ft_withdraws[sample_token_id1] =  {
    '0': 3,
    '1': 2
  }
  assert updated_reactor_state.ft_withdraws == dumps(expected_ft_withdraws)
  assert len(loads(updated_reactor_state.ft_withdraws)) == 1
  assert len(loads(updated_reactor_state.nft_withdraws)) == 0 

def test_atomicalsconsensus_OP_FT_WITHDRAW_incoming_added_multiple_balance_multiple_output():
  payload = {}  
  balances = {}
  balances_incoming = {}
  sample_token_id1 = '012345678901234567890123456789012345678901234567890123456789000000000000'
  sample_token_id1_bytes = bytearray.fromhex(sample_token_id1)
  sample_token_id1_bytes.reverse()
  sample_token_id1_encoded = encode_op_pushdata(sample_token_id1_bytes)
  sample_token_id2 = '712345678901234567890123456789012345678901234567890123456789000000000002'
  sample_token_id2_bytes = bytearray.fromhex(sample_token_id2)
  sample_token_id2_bytes.reverse()
  sample_token_id2_encoded = encode_op_pushdata(sample_token_id2_bytes)
  balances[sample_token_id1] = 2
  balances[sample_token_id2] = 3
  balances_incoming[sample_token_id1] = 3
  balances_incoming[sample_token_id2] = 4
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps(balances_incoming), dumps({}), dumps({}), dumps(balances), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex(sample_token_id1_encoded.hex() + 'd3' + sample_token_id1_encoded.hex() + '00' + '53' + 'f2' + sample_token_id1_encoded.hex() + '51' + '52' + 'f2' + sample_token_id2_encoded.hex() + 'd3' + sample_token_id2_encoded.hex() + '51' + '56' + 'f2'  + '51')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  expected_balances = {}
  expected_balances[sample_token_id2] = 1
  assert updated_reactor_state.ft_balances == dumps(expected_balances)
  assert len(loads(updated_reactor_state.state)) == 0 
  assert len(loads(updated_reactor_state.state_updates)) == 0 
  assert len(loads(updated_reactor_state.state_deletes)) == 0 
  assert len(loads(updated_reactor_state.ft_incoming)) == 2
  assert len(loads(updated_reactor_state.nft_incoming)) == 0 
  assert len(loads(updated_reactor_state.ft_balances)) == 1
  expected_balances_updates = {}
  expected_balances_updates[sample_token_id1] = 0
  expected_balances_updates[sample_token_id2] = 1
  assert updated_reactor_state.ft_balances_updates == dumps(expected_balances_updates)
  assert len(loads(updated_reactor_state.ft_balances_updates)) == 2
  assert len(loads(updated_reactor_state.nft_balances)) == 0 
  assert len(loads(updated_reactor_state.nft_balances_updates)) == 0 
  expected_ft_withdraws = {}
  expected_ft_withdraws[sample_token_id1] =  {
    '0': 3,
    '1': 2
  }
  expected_ft_withdraws[sample_token_id2] =  {
    '1': 6
  }
  assert updated_reactor_state.ft_withdraws == dumps(expected_ft_withdraws)
  assert len(loads(updated_reactor_state.ft_withdraws)) == 2
  assert len(loads(updated_reactor_state.nft_withdraws)) == 0 
