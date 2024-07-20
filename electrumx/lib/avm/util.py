
import re
from electrumx.lib.util import (
  pack_le_uint64
)
from electrumx.lib.util_atomicals import (
  serialize_tx_safe
)
import struct
 
from electrumx.lib.hash import hash_to_hex_str

from bitcointx.core.script import (
 CScriptOp, OP_1NEGATE
)

from bitcointx.core._bignum import (
  bn2vch
)
import random
def sort_protocol_args_by_fn(named_args, protocol_fn):
  params = protocol_fn.get('params')
  if not params:
    return True, []
  sorted_args = []
  for param in params:
    param_name = param['name']
    param_type = param['type']
    if not(param_name in named_args):
      return False, []
    value = named_args[param_name]
    if param_type == 'int':
      if not isinstance(value, int):
        return False, []
      sorted_args.append({
        'type': 'int',
        'value': value
      })
    elif param_type == 'str':
      if not isinstance(value, str):
        return False, []
      sorted_args.append({
        'type': 'str',
        'value': value
      })
    elif param_type == 'bytes':
      if not isinstance(value, bytes):
        return False, []
      sorted_args.append({
        'type': 'bytes',
        'value': value
      })
    else: 
      # Only supports int, str and bytes for now
      return False, []
  return True, sorted_args

def encode_op_pushdata(d):
  """Encode a PUSHDATA op, returning bytes"""
  if len(d) < 0x4c:
      return bytes([len(d)]) + d # OP_PUSHDATA
  elif len(d) <= 0xff:
      return b'\x4c' + bytes([len(d)]) + d # OP_PUSHDATA1
  elif len(d) <= 0xffff:
      return b'\x4d' + struct.pack(b'<H', len(d)) + d # OP_PUSHDATA2
  elif len(d) <= 0xffffffff:
      return b'\x4e' + struct.pack(b'<I', len(d)) + d # OP_PUSHDATA4
  else:
      raise ValueError("Data too long to encode in a PUSHDATA op")

def encode_data_value(somevalue, as_hex=False): 
  if isinstance(somevalue, int):
    if 0 <= somevalue <= 16:
      somevalue = bytes([CScriptOp.encode_op_n(somevalue)])
    elif somevalue == -1:
      somevalue = bytes([OP_1NEGATE])
    else:
      somevalue = CScriptOp.encode_op_pushdata(bn2vch(somevalue))  
  else:
      somevalue = CScriptOp.encode_op_pushdata(somevalue)
 
  if as_hex:
    return somevalue.hex()
  return somevalue

def encode_int_value(somevalue, as_hex=False): 
  if isinstance(somevalue, int):
    if 0 <= somevalue <= 16:
      somevalue = bytes([CScriptOp.encode_op_n(somevalue)])
    elif somevalue == -1:
      somevalue = bytes([OP_1NEGATE])
    else:
      somevalue = CScriptOp.encode_op_pushdata(bn2vch(somevalue))  
  else:
      raise ValueError('not int')
 
  if as_hex:
    return somevalue.hex()
  return somevalue

def encode_args_push_datas_minimal(deploy_sorted_args):
  args_bytes = b''
  for arg in deploy_sorted_args:
    if arg['type'] == 'int':
      if not isinstance(arg['value'], int):
        return False, []
      argval = arg['value']
      args_bytes += encode_data_value(arg['value'])

    elif arg['type'] == 'str':
      if not isinstance(arg['value'], str):
        return False, []
      args_bytes += encode_data_value(arg['value'].encode())

    elif arg['type'] == 'bytes':
      if not isinstance(arg['value'], bytes):
        return False, []
      args_bytes += encode_data_value(arg['value'])

    else: 
      # Only supports int, str and bytes for now
      return False, []
  
  return args_bytes

def validate_protocol_code(code):
  if not code or not isinstance(code, bytes):
    return False
  return True

def is_valid_avm_field_name(field_name):
  if not field_name:
      return False 

  if not isinstance(field_name, str):
      return False
  
  if len(field_name) > 64 or len(field_name) <= 0:
      return False 

  return True

def is_valid_avm_type_name(type_name):
  if not type_name:
      return False 

  if not isinstance(type_name, str):
      return False
  
  if len(type_name) > 64 or len(type_name) <= 0:
      return False 

  return True

def validate_protocol_param(param):
  if not isinstance(param, dict):
    return False 
  
  if not is_valid_avm_field_name(param.get('name')):
    return False 
  
  if not is_valid_avm_type_name(param.get('type')):
    return False 
  
  return True

def validate_protocol_params(params):
  if params and not isinstance(params, list):
    return False
  
  if params:
    param_names = {}
    for param in params: 
      if not validate_protocol_param(param):
        return False
      param_name = param.get('name')
      found_name = param_names.get(param_name)
      if found_name:
        # Name already exists
        return False
      param_names[found_name] = param_name
      
  return True

def validate_protocol_fn_ctor(fn):
  if not fn or not isinstance(fn, dict):
    return False
   
  name = fn.get('name')
  if not is_valid_avm_field_name(name) or name != 'ctor':
    return False
  
  params = fn.get('params')
  if not validate_protocol_params(params):
    return False

  return True

def validate_protocol_p(p):
  if not p:
    return False

  m = re.compile(r'^[a-z][a-z0-9\_]{0,11}$')
  if m.match(p):
      return True
    
  return True

def validate_protocol_fn(fn):
  if not fn or not isinstance(fn, dict):
    return False
   
  name = fn.get('name')
  if not is_valid_avm_field_name(name) or name == 'ctor':
    return False
  
  params = fn.get('params')
  if not validate_protocol_params(params):
    return False
  
  return True

def validate_protocol_fns(fns):
  if not fns or len(fns) == 0 or not isinstance(fns, list):
    return False
  
  if not validate_protocol_fn_ctor(fns[0]):
    return False
  
  function_names = {}
  for fn in fns[1:]:
    if not validate_protocol_fn(fn):
      return False
    fn_name = fn.get('name')
    found_name = function_names.get(fn_name)
    if found_name:
      # Name already exists
      return False
    function_names[found_name] = fn_name

  return True

def validate_protocol_definition(def_data):
  if not def_data or len(def_data) == 0:
    return False, {
      'messages': [
        'Empty'
      ]
    } 
  
  if not validate_protocol_code(def_data.get('code')):
    return False, {
      'messages': [
        'Invalid code'
      ]
    } 
  
  protocol_fns = def_data.get('fn')
  if not validate_protocol_fns(protocol_fns):
    return False, {
      'messages': [
        'Invalid fn'
      ]
    } 
  
  protocol_name = def_data.get('p')
  if not validate_protocol_p(protocol_name):
    False, {
      'messages': [
        'Invalid p'
      ]
    }  
  
  return True, {
      'messages': [
        'Valid'
      ]
    } 

class RequestTxContext:
  def __init__(self, coin, tx_hash, tx, payload):
    self.tx = tx
    rawtx_bytes = serialize_tx_safe(coin, tx_hash, tx)
    self.rawtx_bytes = rawtx_bytes
    self.tx_hash = tx_hash
    self.tx_hash_str = hash_to_hex_str(tx_hash)
    self.payload = payload
    self.auth_public_key = self.payload.get('auth', b'')

class ScriptContext:
  def __init__(self, unlock, lock):
    self.unlock_script = unlock
    self.lock_script = lock

class ReactorContext:
  def __init__(self, state_hash, state, state_updates, state_deletes, nft_incoming, ft_incoming, nft_balances, nft_balances_updates, ft_balances, ft_balances_updates,  nft_withdraws, ft_withdraws):
    if state_hash == None:
      self.state_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    else:
      self.state_hash = state_hash
    
    self.state = state
    self.state_updates = state_updates
    self.state_deletes = state_deletes
    self.ft_incoming = ft_incoming
    self.nft_incoming = nft_incoming
    self.ft_balances = ft_balances
    self.ft_balances_updates = ft_balances_updates
    self.nft_balances = nft_balances
    self.nft_balances_updates = nft_balances_updates
    self.ft_withdraws = ft_withdraws
    self.nft_withdraws = nft_withdraws
 
class RequestBlockchainContext:
  def __init__(self, headers, current_height):
    self.headers = headers
    self.current_height = current_height
 
class RequestInterpretParams:
  def __init__(self, 
               tx_hash, 
               blockchain_context: RequestBlockchainContext, 
               lock_script_code, 
               unlock_script_code, 
               rawtx_bytes):
    self.tx_hash = tx_hash
    self.request_id = hash_to_hex_str(tx_hash)
    self.blockchain_context = blockchain_context
    self.lock_script_code = lock_script_code
    self.unlock_script_code = unlock_script_code
    self.rawtx_bytes = rawtx_bytes

class ResponseError:
  def __init__(self, error_code):
    self.error_code = error_code

class RequestReactorContext:
  def __init__(self, contract_state, ft_balances, nft_balances):
    self.contract_state = contract_state
    self.ft_balances = ft_balances
    self.nft_balances = nft_balances

class ResponseInterpretParams:
  def __init__(self, request_id, state_hash, result_contract_state, result_ft_incoming, result_ft_balances, result_nft_incoming, result_nft_balances, result_ft_withdraws, result_nft_withdraws):
    self.request_id = request_id
    self.state_hash = state_hash
    self.result_contract_state = result_contract_state
    self.result_ft_incoming = result_ft_incoming
    self.result_ft_balances = result_ft_balances
    self.result_nft_incoming = result_nft_incoming
    self.result_nft_balances = result_nft_balances
    self.result_ft_withdraws = result_ft_withdraws
    self.result_nft_withdraws = result_nft_withdraws

    self.validate_state_hash()

  def validate_state_hash(self):
    # Todo: Validate the external state hash provided matches the expected state hash from the calculation here for sanity check
    assert False

 

def print_result_states(obj):
  if isinstance(obj, ResponseInterpretParams):
    print('------------------------------------------------')
    print(f'result_contract_state={r.result_contract_state}')
    print(f'result_ft_balances={r.result_ft_balances}')
    print(f'result_nft_balances={r.result_nft_balances}')
    print(f'result_ft_withdraw={r.result_ft_withdraw}')
    print(f'result_nft_withdraw={r.result_nft_withdraw}')
    print('------------------------------------------------')
  if isinstance(obj, ResponseError):
    print('------------------------------------------------')
    print(f'error_code={r.error_code}')
    print('------------------------------------------------')
