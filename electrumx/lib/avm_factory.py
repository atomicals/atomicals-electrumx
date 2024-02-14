import bitcointx 
 
from electrumx.lib.util_atomicals_formats import (
    is_atomical_id_long_form_bytes,
    is_compact_atomical_id,
    compact_to_location_id_bytes,
    location_id_bytes_to_compact,
    get_tx_hash_index_from_location_id
)

def validate_payload_method_call_format(payload):
  if not payload or len(payload) == 0 or not payload.get('args'):
    return False
  args = payload.get('args')
  call = args.get('call')
  if not call:
    return False
  if not isinstance(call, dict):
    return False
  ids = call.get('ids')
  if not ids or not isinstance(ids, dict):
    return False
  found_one_call = False
  for id_key, request_data in ids.items():
    if not id_key or not isinstance(id_key, bytes):
      return False 
    if not is_atomical_id_long_form_bytes(id_key):
      return False
    # Get the method
    m = request_data.get('m')
    if not isinstance(m, str) or len(m) == 0:
      return False
    # Get the params
    # params can be set as long as it's an array
    p = request_data.get('p', [])
    if p and not isinstance(p, list):
      return False

    for list_item in p:
      if not isinstance(list_item, bytes):
        return False
    found_one_call = True
  if found_one_call:
    return ids
  return False

class ContractCallData:
  def __init__(self):
    pass

class AuthorizedContractCall:
  def __init__(self):
    pass

class AuthorizedContractCallSignature:
  def __init__(self):
    pass 

def is_possible_public_key(k):
  if not isinstance(k, bytes):
      return False 
  return True 

def is_possible_sig(sig):
    if not isinstance(sig, bytes):
        return False 
    return True 
   
class AuthorizedCallFactory:
    def __init__(self, op_data):
        self.authorized_contract_calls = None 
        # Process signature types
        self.pubkey_sig_map = AuthorizedCallFactory.get_public_key_sig_map(op_data['other_input_ops'])
        self.call_method_bytes = AuthorizedCallFactory.get_call_method_bytes(op_data['payload'])

    @classmethod
    def get_public_key_sig_map(self, other_input_ops):
        pubkey_sig_map = {}
        for other_input_op in other_input_ops:
            if other_input_op.get('op') == 's':
                payload = other_input_op.get('payload')
                if payload:
                    for pubkey, sig in payload.items():
                        if is_possible_public_key(pubkey) and is_possible_sig(sig):
                            pubkey_sig_map[pubkey] = {
                                'input_index': other_input_op['input_index'], 
                                'sig': sig
                            }
        return pubkey_sig_map 
    
    @classmethod
    def get_call_method_bytes(self, payload):
        ids = validate_payload_method_call_format(payload)
        if not ids:
          return None 
        
        def serialize_id(id):
          if not isinstance(id, bytes):
            raise ValueError(f'DeveloperError')
          return id
        
        def serialize_method(method):
          if not isinstance(method, str):
            raise ValueError(f'DeveloperError')
          return method.encode()
        
        def serialize_params(params):
          if not isinstance(params, list):
            raise ValueError(f'DeveloperError')
          return b''.join(params)

        call_method_bytes = b''
        for id, value in sorted(ids.items()):
          call_method_bytes += serialize_id(id)
          call_method_bytes += serialize_method(value.get('m'))
          call_method_bytes += serialize_params(value.get('p'))
        return call_method_bytes 
    
    def get_authorized_contract_calls(self):
        return self.authorized_contract_calls

class AVMFactory:
  '''Instantiate the wrapper and factory objects for handling AVM related requests'''
  def __init__(self, logger, atomicals_spent_at_inputs, operations_found_at_inputs):
    self.logger = logger
    self.atomicals_spent_at_inputs = atomicals_spent_at_inputs
    self.operations_found_at_inputs = operations_found_at_inputs
 

  # Determines whether there is a potential callable
  def found_callable(self):
    found_callable_ids = validate_payload_method_call_format(self.operations_found_at_inputs.get('payload'))
    return found_callable_ids
 
  def execute_callable(self):
    if not self.found_callable():
      return False 
    results = {}
    ids = self.operations_found_at_inputs['payload']['args']['call']['ids']
    for atomical_id_contract, request_data in ids.items():
      method = request_data.get('m')
      params = request_data.get('p')
      state = self.get_contract_state(atomical_id_contract)
      result = self._execute_method(state, method, params)
    return False 

  def _execute_method(state, method, params):
    return {}
  
  def get_modified_atomicals_spent_at_inputs(self):
    return self.atomicals_spent_at_inputs
  
  