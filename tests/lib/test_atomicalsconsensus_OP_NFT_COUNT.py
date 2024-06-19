import pytest

from electrumx.lib.coins import Bitcoin
from electrumx.lib.hash import hex_str_to_hash

from electrumx.lib.avm.util import (
    encode_int_value,
    RequestInterpretParams,
    RequestBlockchainContext,
    print_result_states,
    ScriptContext
)
 
from electrumx.lib.avm.avm import (
    RequestBlockchainContext,
    RequestTxContext,
    ReactorContext
)
from bitcointx.core.atomicalsconsensus import (
  ConsensusVerifyScriptAvmExecute
)

from bitcointx.core.script import (
  CScript
)

from cbor2 import dumps

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

def test_atomicalsconsensus_OP_NFT_COUNT_empty_success1():
  payload = {}  
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex('00f90087')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert updated_reactor_state

def test_atomicalsconsensus_OP_NFT_COUNT_nonempty_success1():
  nft_balances = {}
  sample_token_id1 = '012345678901234567890123456789012345678901234567890123456789000000000000'
  nft_balances[sample_token_id1] = True
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps(nft_balances), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  payload = {}  
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex('00f95187')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert updated_reactor_state

def test_atomicalsconsensus_OP_NFT_COUNT_nonempty_success2():
  nft_balances = {}
  sample_token_id1 = '012345678901234567890123456789012345678901234567890123456789000000000000'
  sample_token_id2 = '112345678901234567890123456789012345678901234567890123456789000000000001'
  nft_balances[sample_token_id1] = True
  nft_balances[sample_token_id2] = True
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps(nft_balances), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  payload = {}  
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex('00f95287')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert updated_reactor_state


def test_atomicalsconsensus_OP_NFT_COUNT_incoming_empty_success1():
  payload = {}  
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex('51f90087')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert updated_reactor_state

def test_atomicalsconsensus_OP_NFT_COUNT_incoming_nonempty_success1():
  nft_balances = {}
  sample_token_id1 = '012345678901234567890123456789012345678901234567890123456789000000000000'
  nft_balances[sample_token_id1] = True
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps(nft_balances), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  payload = {}  
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex('51f95187')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert updated_reactor_state

def test_atomicalsconsensus_OP_NFT_COUNT_incoming_nonempty_success2():
  nft_balances = {}
  sample_token_id1 = '012345678901234567890123456789012345678901234567890123456789000000000000'
  sample_token_id2 = '112345678901234567890123456789012345678901234567890123456789000000000001'
  nft_balances[sample_token_id1] = True
  nft_balances[sample_token_id2] = True
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  reactor_context = ReactorContext(state_hash, dumps({}), dumps({}), dumps({}), dumps(nft_balances), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  payload = {}  
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(), CScript(bytes.fromhex('51f95287')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
  assert updated_reactor_state