import pytest

from electrumx.lib.coins import Bitcoin

from electrumx.lib.avm.avm import (
    AVMFactory
)

from electrumx.lib.avm.avm import (
    AVMFactory,
    RequestBlockchainContext,
    RequestTxContext,
    ReactorContext
)

from electrumx.lib.avm.util import (
    encode_int_value,
    RequestBlockchainContext,
)

from bitcointx.core.atomicalsconsensus import (
  AtomicalConsensusExecutionError
)

from electrumx.lib.avm.util import (
    encode_int_value,
    RequestBlockchainContext,
    RequestInterpretParams,
    encode_op_pushdata,
    print_result_states
)
from electrumx.lib.avm.pow_funcs import (
    calc_sha3_256,
    calc_sha512,
    calc_sha512_256,
    calc_eaglesong
)
  
from bitcointx.core.atomicalsconsensus import (
  ConsensusVerifyScriptAvmExecute
)

from bitcointx.core.script import (
  CScript
)
from bitcointx.core._bignum import (
  bn2vch
)

from cbor2 import dumps, loads, CBORDecodeError

mock_block_header = '000000209174c9f2757e2647733c9ab69c133b90257f85ce7e9c0100000000000000000096e490f16d161416bef825bd4716b0914f344be5835cf6a8f0de89288a6c440391af0566d3620317aca8414a'
  
mock_contract_external_state_cbor = dumps({
      'header': mock_block_header,
      'height': 820123
})


coin = Bitcoin

class MockLogger:
    def debug(self, msg):
        return 
    def info(self, msg):
        return 
    def warning(self, msg):
        return 
   
def mock_mint_fetcher(atomical_id):
  return {}

mock_current_header = '000000209174c9f2757e2647733c9ab69c133b90257f85ce7e9c0100000000000000000096e490f16d161416bef825bd4716b0914f344be5835cf6a8f0de89288a6c440391af0566d3620317aca8414a'
mock_headers = {
    '840012': mock_current_header
}
mock_blockchain_context = RequestBlockchainContext(mock_headers, 840012)
mock_rawtx = bytes.fromhex('02000000018e469f953413e8d865fcf1f47d759772aa05e8d78b1e4577a58edc8bd09344ff010000006b483045022100ce16646785907c919a1658496a85cf3f3d877d98ffca5eabd189524acc1de53b02205ac24a9e2855db3da26b840c82fddaf73a5a6eff4b5b78cadfb00584ad6bd5f3012102cbcad7b21fb5fb08ad55eb09e327b97f63e8c5e99b2faf9bb330545a5bd4602cfeffffff0203761700000000001976a91496d02c013f734a642871261324c58091a806c23188ac9ce52300000000001976a914a9a8d5aa3ec73688d0540d45be3842f4603705c588ac6e640800')
mock_tx, mock_tx_hash = coin.DESERIALIZER(mock_rawtx, 0).read_tx_and_hash()
mock_empty_reactor_context = ReactorContext(None, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))

def test_atomicalsconsensus_OP_HASH_FN_SHA3_256_success1():
  sha3_256_preimage = '12345678901234567890'
  sha3_256_preimage_bytes = bytes.fromhex(sha3_256_preimage)
  sha3_256_hash_value = calc_sha3_256(sha3_256_preimage_bytes)
  sha3_256_preimage_bytes_encoded = encode_op_pushdata(sha3_256_preimage_bytes)
  to_hash_value_data = encode_op_pushdata(sha3_256_hash_value)
 
  assert('8f9e20c10b08813adeb3027e464f3bbe6f0f2220536a4ec2cd9b03444e18a8ad' == sha3_256_hash_value.hex())
  lock_script = sha3_256_preimage_bytes_encoded.hex() + '00fd' + to_hash_value_data.hex() + '87'
  protocol_mint_data = {
    'p': 'ppp',
    'code': bytes.fromhex(lock_script),
    'fn': [
        {
            'name': 'ctor',
            'params': [
            ]
        }
    ]
  }
  deploy_payload = {
    'op': 'deploy',
    'p': 'ppp',
    'args': {
    }
  }

  avm = AVMFactory(MockLogger(), mock_mint_fetcher, mock_blockchain_context, protocol_mint_data)
  atomicals_spent_at_inputs = {}
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, deploy_payload)
  deploy_command = avm.create_deploy_command(request_tx_context, atomicals_spent_at_inputs, mock_empty_reactor_context)
  assert(deploy_command.is_valid)
  assert(deploy_command.unlock_script.hex() == '')
  assert(deploy_command.lock_script.hex() == lock_script)
  result = deploy_command.execute() 
  assert result.success 

def test_atomicalsconsensus_OP_HASH_FN_SHA3_256_delete1():
  with pytest.raises(AtomicalConsensusExecutionError) as exc:
    sha3_256_preimage = '9999'
    sha3_256_preimage_bytes = bytes.fromhex(sha3_256_preimage)
    sha3_256_hash_value = calc_sha3_256(sha3_256_preimage_bytes)
    to_hash_value_data = encode_op_pushdata(sha3_256_hash_value)
    different_bytes = encode_op_pushdata(b'123')
    lock_script = different_bytes.hex() + '00fd' + to_hash_value_data.hex() + '87'
    protocol_mint_data = {
      'p': 'ppp',
      'code': bytes.fromhex(lock_script),
      'fn': [
          {
              'name': 'ctor',
              'params': [
              ]
          }
      ]
    }
    deploy_payload = {
      'op': 'deploy',
      'p': 'ppp',
      'args': {
      }
    }

    avm = AVMFactory(MockLogger(), mock_mint_fetcher, mock_blockchain_context, protocol_mint_data)
    atomicals_spent_at_inputs = {}
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, deploy_payload)
    deploy_command = avm.create_deploy_command(request_tx_context, atomicals_spent_at_inputs, mock_empty_reactor_context)
    assert(deploy_command.is_valid)
    assert(deploy_command.unlock_script.hex() == '')
    assert(deploy_command.lock_script.hex() == lock_script)
    deploy_command.execute() 
    
  assert exc.value.error_code == 0
  assert exc.value.script_error == 2
  assert exc.value.script_error_op_num == 4

def test_atomicalsconsensus_OP_HASH_FN_SHA512_success1():
  preimage = '12345678901234567890'
  preimage_bytes = bytes.fromhex(preimage)
  hash_value = calc_sha512(preimage_bytes)
  preimage_bytes_encoded = encode_op_pushdata(preimage_bytes)
  to_hash_value_data = encode_op_pushdata(hash_value)
  assert('cda7e420d1669a40d5511d4ba48d5d9b2df052ad3f81af429fdf77b4786f9507f3ff95b2206c287accb43f6bb3a98a821dbffee4947a09b77cb90b4d2874df42' == hash_value.hex())
  lock_script = preimage_bytes_encoded.hex() + '51fd' + to_hash_value_data.hex() + '87'
  protocol_mint_data = {
    'p': 'ppp',
    'code': bytes.fromhex(lock_script),
    'fn': [
        {
            'name': 'ctor',
            'params': [
            ]
        }
    ]
  }
  deploy_payload = {
    'op': 'deploy',
    'p': 'ppp',
    'args': {
    }
  }

  avm = AVMFactory(MockLogger(), mock_mint_fetcher, mock_blockchain_context, protocol_mint_data)
  atomicals_spent_at_inputs = {}
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, deploy_payload)
  deploy_command = avm.create_deploy_command(request_tx_context, atomicals_spent_at_inputs, mock_empty_reactor_context)
  assert(deploy_command.is_valid)
  assert(deploy_command.unlock_script.hex() == '')
  assert(deploy_command.lock_script.hex() == lock_script)
  result = deploy_command.execute() 
  assert result.success 

def test_atomicalsconsensus_OP_HASH_FN_SHA512_256_success1():
  preimage = '12345678901234567890'
  preimage_bytes = bytes.fromhex(preimage)
  hash_value = calc_sha512_256(preimage_bytes)
  preimage_bytes_encoded = encode_op_pushdata(preimage_bytes)
  to_hash_value_data = encode_op_pushdata(hash_value)
 
  assert('f7c1a111dc74c4cafe5d6a0aa265c1f1592d3759fee2faaefe3080f5e6bb57f4' == hash_value.hex())
  lock_script = preimage_bytes_encoded.hex() + '52fd' + to_hash_value_data.hex() + '87'
  protocol_mint_data = {
    'p': 'ppp',
    'code': bytes.fromhex(lock_script),
    'fn': [
        {
            'name': 'ctor',
            'params': [
            ]
        }
    ]
  }
  deploy_payload = {
    'op': 'deploy',
    'p': 'ppp',
    'args': {
    }
  }

  avm = AVMFactory(MockLogger(), mock_mint_fetcher, mock_blockchain_context, protocol_mint_data)
  atomicals_spent_at_inputs = {}
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, deploy_payload)
  deploy_command = avm.create_deploy_command(request_tx_context, atomicals_spent_at_inputs, mock_empty_reactor_context)
  assert(deploy_command.is_valid)
  assert(deploy_command.unlock_script.hex() == '')
  assert(deploy_command.lock_script.hex() == lock_script)
  result = deploy_command.execute() 
  assert result.success 


def test_atomicalsconsensus_OP_HASH_FN_eaglesong_success1():
  preimage = '12345678901234567890'
  preimage_bytes = bytes.fromhex(preimage)
  hash_value = calc_eaglesong(preimage_bytes)
  preimage_bytes_encoded = encode_op_pushdata(preimage_bytes)
  to_hash_value_data = encode_op_pushdata(hash_value)
  assert('087e1c61707d800e15a904abe09ec03bb18829a33a919073180c3587bdfb3385' == hash_value.hex())
  lock_script = preimage_bytes_encoded.hex() + '53fd' + to_hash_value_data.hex() + '87'
  protocol_mint_data = {
    'p': 'ppp',
    'code': bytes.fromhex(lock_script),
    'fn': [
        {
            'name': 'ctor',
            'params': [
            ]
        }
    ]
  }
  deploy_payload = {
    'op': 'deploy',
    'p': 'ppp',
    'args': {
    }
  }

  avm = AVMFactory(MockLogger(), mock_mint_fetcher, mock_blockchain_context, protocol_mint_data)
  atomicals_spent_at_inputs = {}
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, deploy_payload)
  deploy_command = avm.create_deploy_command(request_tx_context, atomicals_spent_at_inputs, mock_empty_reactor_context)
  assert(deploy_command.is_valid)
  assert(deploy_command.unlock_script.hex() == '')
  assert(deploy_command.lock_script.hex() == lock_script)
  result = deploy_command.execute() 
  assert result.success 