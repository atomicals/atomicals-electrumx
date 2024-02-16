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

# A contract method call can be signed by a user or unsigned
# This is just the data structure to store and the authorization and checking if a method call
# must be authorized is done elsewhere before exection of the contract
class ContractMethodCall:
  def __init__(self, contract_id, method_name, params_list, signed_by):
    pass

class MethodCallCallFactory:
    def __init__(self, prev_outpoint, op_data):
        if not prev_outpoint or not op_data:
          raise ValueError('DeveloperError')
        self.prev_outpoint = prev_outpoint
        self.op_data = op_data
        # Process signature types
        self.pubkey_sig_map = MethodCallCallFactory.get_public_key_sig_map(op_data['other_input_ops'])
        self.call_method_bytes = MethodCallCallFactory.get_call_method_bytes(op_data['payload'])
        self.contract_call = MethodCallCallFactory.create_contract_calls(self.pubkey_sig_map, self.get_bytes_to_sign())

    @classmethod    
    def is_possible_public_key(cls, k):
      if not isinstance(k, bytes):
          return False 
      return True 
    
    @classmethod
    def is_possible_sig(cls, sig):
      if not isinstance(sig, bytes):
          return False 
      return True 

    @classmethod
    def create_contract_call(cls, pubkey_sigs, bytes_to_sign):
      return ContractMethodCall() 
    
    @classmethod
    def get_contract_call(self):
      return self.contract_call
    
    @classmethod
    def get_public_key_sig_map(cls, other_input_ops):
        pubkey_sig_map = {}
        for other_input_op in other_input_ops:
            if other_input_op.get('op') == 's':
                payload = other_input_op.get('payload')
                if payload:
                    for pubkey, sig_data in payload.items():
                        if AuthorizedCallFactory.is_possible_public_key(pubkey) and AuthorizedCallFactory.is_possible_sig(sig_data.get('sig')):
                            pubkey_sig_map[pubkey] = {
                                'index': other_input_op['index'], 
                                'sig': sig_data.get('sig')
                            }
        return pubkey_sig_map 
    
    def get_bytes_to_sign(self):
      return self.prev_outpoint + self.call_method_bytes
       
    @classmethod
    def get_call_method_bytes(cls, payload):
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
    self.found_callable_ids = validate_payload_method_call_format(self.operations_found_at_inputs.get('payload'))
 
  # Determines whether there is a potential callable
  def found_callable(self):
    return found_callable_ids
 
  # Get the contract callable interface and validate authorizations
  # Check things like:
  # 1. Correct version of callable code
  # 2. Authorized methods requiring signatures
  # 3. Payable versus non-payable
  def prepare_callable_context(self):
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
  
  