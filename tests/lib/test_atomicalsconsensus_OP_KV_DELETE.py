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
mock_empty_reactor_context = ReactorContext(None, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
 
def test_atomicalsconsensus_OP_KV_DELETE_1():
  payload = {}  
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  reactor_context = ReactorContext(state_hash, dumps({
    "02": {
      "00": "68656c6c6f"
    }
  }), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(bytes.fromhex('0177020004021234')), CScript(bytes.fromhex('f00177020004ef02123487750177020004f10177020004ed0087')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
   
  assert loads(updated_reactor_state.state) == {
      "02": {
        "00": "68656c6c6f"
      }
  }
  state = loads(updated_reactor_state.state)
  state_updates = loads(updated_reactor_state.state_updates)
  state_deletes = loads(updated_reactor_state.state_deletes)
  ft_incoming = loads(updated_reactor_state.ft_incoming)
  nft_incoming = loads(updated_reactor_state.nft_incoming)
  ft_balances = loads(updated_reactor_state.ft_balances)
  ft_balances_updates = loads(updated_reactor_state.ft_balances_updates)
  nft_balances = loads(updated_reactor_state.nft_balances)
  nft_balances_updates = loads(updated_reactor_state.nft_balances_updates)
  ft_withdraws = loads(updated_reactor_state.ft_withdraws)
  nft_withdraws = loads(updated_reactor_state.nft_withdraws)
  
  assert updated_reactor_state.state_hash.hex() == '8d6b9400c2906a0ec3fd75ce432b18a43f7974e698efa99e736d32d2eb89f383'
  assert len(state) == 1
  assert len(state_updates) == 0
  assert len(state_deletes) == 1
  assert state_deletes == {'77': {'0004': True}}
  assert len(ft_incoming) == 0 
  assert len(nft_incoming) == 0 
  assert len(ft_balances) == 0 
  assert len(ft_balances_updates) == 0 
  assert len(nft_balances) == 0 
  assert len(nft_balances_updates) == 0 
  assert len(ft_withdraws) == 0 
  assert len(nft_withdraws) == 0 
   
def test_atomicalsconsensus_OP_KV_DELETE_2():
  payload = {}  
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, payload)
  state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
  reactor_context = ReactorContext(state_hash, dumps({
    "02": {
      "00": "68656c6c6f"
    }
  }), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))
  blockchain_context = RequestBlockchainContext(mock_headers, 840012)
  script_context = ScriptContext(CScript(bytes.fromhex('0177020004021234')), CScript(bytes.fromhex('f00177020004ef02123487750177020004f10177020004ed5200f10087')))
  updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, blockchain_context, request_tx_context, reactor_context)
 
  state = loads(updated_reactor_state.state)
  state_updates = loads(updated_reactor_state.state_updates)
  state_deletes = loads(updated_reactor_state.state_deletes)
  ft_incoming = loads(updated_reactor_state.ft_incoming)
  nft_incoming = loads(updated_reactor_state.nft_incoming)
  ft_balances = loads(updated_reactor_state.ft_balances)
  ft_balances_updates = loads(updated_reactor_state.ft_balances_updates)
  nft_balances = loads(updated_reactor_state.nft_balances)
  nft_balances_updates = loads(updated_reactor_state.nft_balances_updates)
  ft_withdraws = loads(updated_reactor_state.ft_withdraws)
  nft_withdraws = loads(updated_reactor_state.nft_withdraws)
  
  assert state == {}
  assert state_updates == {}
  assert updated_reactor_state.state_hash.hex() == '6918702d8b95869ac1fce0522827d4641052a95cb34eb8dab4b2225594941b02'
  assert len(state) == 0
  assert len(state_updates) == 0
  assert len(state_deletes) == 2
  assert state_deletes == {'02': {'00': True}, '77': {'0004': True}}
  assert len(ft_incoming) == 0 
  assert len(nft_incoming) == 0 
  assert len(ft_balances) == 0 
  assert len(ft_balances_updates) == 0 
  assert len(nft_balances) == 0 
  assert len(nft_balances_updates) == 0 
  assert len(ft_withdraws) == 0 
  assert len(nft_withdraws) == 0 
  