import pytest

from cbor2 import dumps 
from electrumx.lib.coins import Bitcoin
from electrumx.lib.hash import hex_str_to_hash
from electrumx.lib.avm.avm import (
    AVMFactory,
    RequestBlockchainContext,
    RequestTxContext,
    ReactorContext
)
from electrumx.lib.avm.util import (
    encode_int_value,
    encode_op_pushdata,
    RequestBlockchainContext,
)
from bitcointx.core.atomicalsconsensus import (
  AtomicalConsensusExecutionError
)

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

def test_atomicalsconsensus_OP_DECODEBLOCKINFO_fail_header_size():
  mock_current_header_wrong_len = bytes.fromhex(mock_current_header) + b'01'
  mock_current_header_wrong_len_encoded = encode_op_pushdata(mock_current_header_wrong_len)
  
  protocol_mint_data = {
    'p': 'ppp',
    'code': bytes.fromhex(mock_current_header_wrong_len_encoded.hex() + '59fc5187'),
    'fn': [
        {
            'name': 'ctor',
            'params': [
            ]
        }
    ]
  }
  deploy_payload = {
    'p': 'ppp',
    'u': b'',
    'args': {
    }
  }

  avm = AVMFactory(MockLogger(), mock_mint_fetcher, mock_blockchain_context, protocol_mint_data)
  atomicals_spent_at_inputs = {}
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, deploy_payload)
  deploy_command = avm.create_deploy_command(request_tx_context, atomicals_spent_at_inputs, mock_empty_reactor_context)
  assert(deploy_command.is_valid)
  assert(deploy_command.unlock_script.hex() == '')
  assert(deploy_command.lock_script.hex() == '4c52000000209174c9f2757e2647733c9ab69c133b90257f85ce7e9c0100000000000000000096e490f16d161416bef825bd4716b0914f344be5835cf6a8f0de89288a6c440391af0566d3620317aca8414a303159fc5187')
  result = deploy_command.execute() 
  assert not result.success 
  assert not result.reactor_context
  assert result.error.error_code == 0
  assert result.error.script_error == 77
  assert result.error.script_error_op_num == 2
 
def test_atomicalsconsensus_OP_DECODEBLOCKINFO_invalid_item():
  mock_current_header_wrong_len = bytes.fromhex(mock_current_header)
  mock_current_header_wrong_len_encoded = encode_op_pushdata(mock_current_header_wrong_len)
  
  protocol_mint_data = {
    'p': 'ppp',
    'code': bytes.fromhex(mock_current_header_wrong_len_encoded.hex() + '57fc5187'),
    'fn': [
        {
            'name': 'ctor',
            'params': [
            ]
        }
    ]
  }
  deploy_payload = {
    'p': 'ppp',
    'u': b'',
    'args': {
    }
  }

  avm = AVMFactory(MockLogger(), mock_mint_fetcher, mock_blockchain_context, protocol_mint_data)
  atomicals_spent_at_inputs = {}
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, deploy_payload)
  deploy_command = avm.create_deploy_command(request_tx_context, atomicals_spent_at_inputs, mock_empty_reactor_context)
  assert(deploy_command.is_valid)
  assert(deploy_command.unlock_script.hex() == '')
  assert(deploy_command.lock_script.hex() == '4c50000000209174c9f2757e2647733c9ab69c133b90257f85ce7e9c0100000000000000000096e490f16d161416bef825bd4716b0914f344be5835cf6a8f0de89288a6c440391af0566d3620317aca8414a57fc5187')

  result = deploy_command.execute() 
  assert not result.success 
  assert not result.reactor_context
  assert result.error.error_code == 0
  assert result.error.script_error == 76
  assert result.error.script_error_op_num == 2
  
def test_atomicalsconsensus_OP_DECODEBLOCKINFO_deploy_success_items():
  block_header = '000000209174c9f2757e2647733c9ab69c133b90257f85ce7e9c0100000000000000000096e490f16d161416bef825bd4716b0914f344be5835cf6a8f0de89288a6c440391af0566d3620317aca8414a'
  block_header_encoded = encode_op_pushdata(bytes.fromhex(block_header))
  block_items = [
     {
        'field': 0,
        'field_enc': '00',
        'result': '0400000020'
     },
      {
        'field': 1,
        'field_enc': '51',
        'result': '20' + '9174c9f2757e2647733c9ab69c133b90257f85ce7e9c01000000000000000000'
     },
      {
        'field': 2,
        'field_enc': '52',
        'result': '20' + '96e490f16d161416bef825bd4716b0914f344be5835cf6a8f0de89288a6c4403'
     },
      {
        'field': 3,
        'field_enc': '53',
        'result': encode_int_value(1711648657).hex()
     },
      {
        'field': 4,
        'field_enc': '54',
        'result': encode_int_value(386097875).hex(),
     },
      {
        'field': 5,
        'field_enc': '55',
        'result': encode_int_value(1245817004).hex()
     },
      {
        'field': 6,
        'field_enc': '56',
        'result': encode_int_value(83126997340025).hex()
     }
  ]
  for item in block_items:
    lock_script = 'fc' + item['result'] + '87'
    protocol_mint_data = {
        'p': 'ppp',
        'code': bytes.fromhex(lock_script),
        'fn': [
            {
                'name': 'ctor',
                'params': [
                      {
                          'name': 'header',
                          'type': 'bytes'
                      },
                      {
                          'name': 'field',
                          'type': 'int'
                      } 
                  ]
            }
        ]
    }
    deploy_payload = {
      'p': 'ppp',
      'u': bytes.fromhex(block_header_encoded.hex() + item['field_enc']),
      'args': {
      }
    }
    avm = AVMFactory(MockLogger(), mock_mint_fetcher, mock_blockchain_context, protocol_mint_data)
    atomicals_spent_at_inputs = {}
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, deploy_payload)
    deploy_command = avm.create_deploy_command(request_tx_context, atomicals_spent_at_inputs, mock_empty_reactor_context)
    assert(deploy_command.is_valid)
    assert(deploy_command.unlock_script.hex() == block_header_encoded.hex() + item['field_enc'])
    assert(deploy_command.lock_script.hex() == lock_script)
    result = deploy_command.execute() 
    assert result.success 
 