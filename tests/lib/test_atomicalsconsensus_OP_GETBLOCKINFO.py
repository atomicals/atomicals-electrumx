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
mock_empty_reactor_context = ReactorContext(None, dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}), dumps({}))

def test_atomicalsconsensus_OP_GETBLOCKINFO_fail_missing_fields():
  protocol_mint_data = {
    'p': 'ppp',
    'code': bytes.fromhex('0059fb5187'),
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
  assert(deploy_command.lock_script.hex() == '0059fb5187')

  result = deploy_command.execute() 
  assert not result.success 
  assert not result.reactor_context
  assert result.error.error_code == 0
  assert result.error.script_error == 76
  assert result.error.script_error_op_num == 2

def test_atomicalsconsensus_OP_GETBLOCKINFO_current_00_success():
  encoded_height = encode_int_value(840012).hex()
  lock_script = '0058fb' + encoded_height + '87'
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
   
def test_atomicalsconsensus_OP_GETBLOCKINFO_deploy_success1():
  block_header = '000000209174c9f2757e2647733c9ab69c133b90257f85ce7e9c0100000000000000000096e490f16d161416bef825bd4716b0914f344be5835cf6a8f0de89288a6c440391af0566d3620317aca8414a'
  lock_script = 'fb' + '4c50' + block_header + '87'
  protocol_mint_data = {
      'p': 'ppp',
      'code': bytes.fromhex(lock_script),
      'fn': [
          {
              'name': 'ctor',
              'params': [
                    {
                        'name': 'height',
                        'type': 'int'
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
    'u': bytes.fromhex('0057'),
    'args': {
    }
  }
  avm = AVMFactory(MockLogger(), mock_mint_fetcher, mock_blockchain_context, protocol_mint_data)
  atomicals_spent_at_inputs = {}
  request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, deploy_payload)
  deploy_command = avm.create_deploy_command(request_tx_context, atomicals_spent_at_inputs, mock_empty_reactor_context)
  assert(deploy_command.is_valid)
  assert(deploy_command.unlock_script.hex() == '0057')
  assert(deploy_command.lock_script.hex() == lock_script)
  result = deploy_command.execute() 
  assert result.success 

def test_atomicalsconsensus_OP_GETBLOCKINFO_deploy_success_items():
  block_header = '000000209174c9f2757e2647733c9ab69c133b90257f85ce7e9c0100000000000000000096e490f16d161416bef825bd4716b0914f344be5835cf6a8f0de89288a6c440391af0566d3620317aca8414a'
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
     },
      {
        'field': 7,
        'field_enc': '57',
        'result': '4c50' + block_header
     },
     {
        'field': 8,
        'field_enc': '58',
        'result': encode_int_value(840012).hex()
     }
  ]

  i = 0

  for item in block_items:
    lock_script = 'fb' + item['result'] + '87'
    protocol_mint_data = {
        'p': 'ppp',
        'code': bytes.fromhex(lock_script),
        'fn': [
            {
                'name': 'ctor',
                'params': [
                      {
                          'name': 'height',
                          'type': 'int'
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
      'u': bytes.fromhex('00' + item['field_enc']),
      'args': {
      }
    }
    avm = AVMFactory(MockLogger(), mock_mint_fetcher, mock_blockchain_context, protocol_mint_data)
    atomicals_spent_at_inputs = {}
    request_tx_context = RequestTxContext(coin, mock_tx_hash, mock_tx, deploy_payload)
    deploy_command = avm.create_deploy_command(request_tx_context, atomicals_spent_at_inputs, mock_empty_reactor_context)
    assert(deploy_command.is_valid)
    assert(deploy_command.unlock_script.hex() == '00' + item['field_enc'])
    assert(deploy_command.lock_script.hex() == lock_script)
    result = deploy_command.execute() 
    assert result.success 
 