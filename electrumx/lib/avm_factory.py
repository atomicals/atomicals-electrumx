import bitcointx 
from electrumx.lib.util_atomicals import is_atomical_id_long_form_bytes

class AVMFactory:
  '''Instantiate the wrapper and factory objects for handling AVM related requests'''
  def __init__(self, logger, atomicals_spent_at_inputs, operations_found_at_inputs):
    self.logger = logger
    self.atomicals_spent_at_inputs = atomicals_spent_at_inputs
    self.operations_found_at_inputs = operations_found_at_inputs

  # Determines whether there is a potential callable
  def found_callable(self):
    payload = self.operations_found_at_inputs.get('payload')
    if not payload or len(payload) == 0 or not payload.get('args'):
      return False
    args = payload.get('args')
    call = args.get('call')
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
      # params can be set as long as it's a dictionary
      p = request_data.get('p')
      if p and not isinstance(p, dict):
        return False
      found_one_call = True
    return found_one_call 
 
  def process_callable(self):
    return False 
  
  def get_modified_atomicals_spent_at_inputs(self):
    return self.atomicals_spent_at_inputs
  
  