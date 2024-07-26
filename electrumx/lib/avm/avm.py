from bitcointx.core.atomicalsconsensus import (
  ConsensusVerifyScriptAvmExecute,
  AtomicalConsensusExecutionError
)

from bitcointx.core.script import (
  CScript
)
from electrumx.lib.avm.util import (
  validate_protocol_definition,
  sort_protocol_args_by_fn,
  encode_args_push_datas_minimal,
  RequestBlockchainContext,
  RequestTxContext,
  ReactorContext,
  RequestBlockchainContext,
  ScriptContext
) 
from electrumx.lib.atomicals_blueprint_builder import AtomicalsTransferBlueprintBuilder
from cbor2 import loads

class CallCommandResult:
  def __init__(self, success, reactor_context, error=None):
    self.success = success
    self.reactor_context = reactor_context
    self.error = error

class CallCommand:
  def __init__(self, logger, blockchain_context: RequestBlockchainContext, request_tx_context: RequestTxContext, protocol_mint_data, atomicals_spent_at_inputs, reactor_state: ReactorContext, reactor_atomical_mint_info):
    self.logger = logger
    self.blockchain_context = blockchain_context
    self.request_tx_context = request_tx_context
    self.reactor_atomical_mint_info = reactor_atomical_mint_info
    self.atomicals_spent_at_inputs = atomicals_spent_at_inputs
    self.protocol_mint_data = protocol_mint_data
    self.reactor_state = reactor_state
    is_valid, unlock_script, lock_script = self.validate_params()
    self.is_valid = is_valid
    self.unlock_script = unlock_script
    self.lock_script = lock_script

  def prepare_call_script(self, protocol_mint_data, call_payload):
    if not protocol_mint_data:
      return False, None, None 
    
    protocol_code = protocol_mint_data.get('code')
    if not protocol_code:
      return False, None, None 
    
    reactor_name = call_payload.get('n')
    if not reactor_name:
      return False, None, None 
 
    # method = call_payload.get('m')
    # if not isinstance(method, int) or method <= 0:
    #   return False, None, None 
  
    # success, status = validate_protocol_definition(protocol_mint_data)
    # if not success:
    #   return False, None, None 
   
    # named_axdgs = call_payload.get('args')
    # protocol_fns = protocol_mint_data.get('fn')
    # found_all_params, sorted_args = sort_protocol_args_by_fn(named_args, protocol_fns[method])
    # if not found_all_params:
    #  return False, None, None
    # sorted_args_encoded_script = encode_args_push_datas_minimal(sorted_args)
    # sorted_args_encoded_script += bytes.fromhex('00') # attach an OP_FALSE at the top to indicate it will execute the deploy branch of the script
   
    return True, call_payload.get('u', b''), protocol_code

  def validate_params(self):
    # todo: do some sanity check to ensure the protocol code matches for the reactor with reactor_atomical_mint_info
    validated_success, unlock_script, lock_script = self.prepare_call_script(self.protocol_mint_data, self.request_tx_context.payload)
    return validated_success, unlock_script, lock_script
  
  def execute(self):
    if not self.is_valid:
      raise ValueError(f'execute fail not valid call setup')
    
    # Null dummy cbor context is not actually used by consensus library, but we pass in dummy data
    script_context = ScriptContext(CScript(self.unlock_script), CScript(self.lock_script))
    # Sanity check that the reactor context has the defaults, the only values allowed to be set are the nft_incoming and ft_incoming
    assert self.reactor_state.state_hash != None and len(self.reactor_state.state_hash) == 32
    # Just check state and balances decode correctly
    loads(self.reactor_state.state)
    loads(self.reactor_state.nft_balances)
    loads(self.reactor_state.ft_balances) 
    # Ensure the withdraws are empty because they will be set later
    assert loads(self.reactor_state.nft_withdraws) == {}
    assert loads(self.reactor_state.ft_withdraws) == {}
    # just check correctly decode cbor for nft_incoming and ft_incoming
    loads(self.reactor_state.nft_incoming)
    loads(self.reactor_state.ft_incoming)
    try:
      updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, self.blockchain_context, self.request_tx_context, self.reactor_state)
      # Quite overkill to deserialize entire CBOR, but we want to be sure a valid CBOR was returned
      loads(updated_reactor_state.state)
      loads(updated_reactor_state.ft_balances)
      loads(updated_reactor_state.nft_balances)
      print(f'updated_reactor_state.state={loads(updated_reactor_state.state)}')
      print(f'updated_reactor_state.ft_balances={loads(updated_reactor_state.ft_balances)}')
      print(f'updated_reactor_state.nft_balances={loads(updated_reactor_state.nft_balances)}')
      if updated_reactor_state:
        # Todo: Only clear off the atomicals here that were actually accepted by the script
        self.request_tx_context.atomicals_spent_at_inputs = {}
        # Todo: Color the FT/NFT outputs
        return CallCommandResult(True, updated_reactor_state)
    except AtomicalConsensusExecutionError as ex:
      print(f'AtomicalConsensusExecutionError ex={ex}')
      return CallCommandResult(False, ex)
    
    raise ValueError(f'Critical call error')
  
class DeployCommandResult:
  def __init__(self, success, reactor_context, error=None):
    self.success = success
    self.reactor_context = reactor_context
    self.error = error

class DeployCommand:
  def __init__(self, logger, blockchain_context: RequestBlockchainContext, request_tx_context: RequestTxContext, protocol_mint_data, atomicals_spent_at_inputs, reactor_state: ReactorContext):
    self.logger = logger
    self.atomicals_spent_at_inputs = atomicals_spent_at_inputs
    self.blockchain_context = blockchain_context
    self.request_tx_context = request_tx_context
    self.protocol_mint_data = protocol_mint_data
    is_valid, unlock_script, lock_script = self.validate_params()
    self.is_valid = is_valid
    self.unlock_script = unlock_script
    self.lock_script = lock_script
    self.reactor_state = reactor_state

  def prepare_deploy_script(self, protocol_mint_data, deploy_payload):
    if not protocol_mint_data:
      return False, None, None 
    protocol_code = protocol_mint_data.get('code')
    if not protocol_code:
      return False, None, None 
    # print(f'prepare_deploy_script:3')
    # success, status = validate_protocol_definition(protocol_mint_data)
    # if not success:
    #   return False, None, None 
    # print(f'prepare_deploy_script:4')
    # deploy_named_args = deploy_payload.get('args')
    # protocol_fns = protocol_mint_data.get('fn')
    # found_all_params, deploy_sorted_args = sort_protocol_args_by_fn(deploy_named_args, protocol_fns[0])
    # if not found_all_params:
    #  return False, None, None
    # print(f'prepare_deploy_script:5')
    # deploy_sorted_args_encoded_script = encode_args_push_datas_minimal(deploy_sorted_args)
    # print(f'prepare_deploy_script:6')
    # deploy_sorted_args_encoded_script = bytes.fromhex('00') # attach an OP_FALSE at the top to indicate it will execute the deploy branch of the script
    return True, deploy_payload.get('u', b''), protocol_code
  
  def validate_params(self):
    validated_success, unlock_script, lock_script = self.prepare_deploy_script(self.protocol_mint_data, self.request_tx_context.payload)
    return validated_success, unlock_script, lock_script
  
  def execute(self):
    if not self.is_valid:
      raise ValueError(f'execute fail not valid deploy setup')
    
    # Null dummy cbor context is not actually used by consensus library, but we pass in dummy data
    script_context = ScriptContext(CScript(self.unlock_script), CScript(self.lock_script))
 
    # Sanity check that the reactor context has the defaults, the only values allowed to be set are the nft_incoming and ft_incoming
    assert self.reactor_state.state_hash == bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    # Ensure the datas are empty because they will be set later
    assert loads(self.reactor_state.state) == {}
    assert loads(self.reactor_state.nft_balances) == {}
    assert loads(self.reactor_state.ft_balances) == {}
    assert loads(self.reactor_state.nft_withdraws) == {}
    assert loads(self.reactor_state.ft_withdraws) == {}
    # just check correctly decode cbor for nft_incoming and ft_incoming
    loads(self.reactor_state.nft_incoming)
    loads(self.reactor_state.ft_incoming)

    try:
      updated_reactor_state = ConsensusVerifyScriptAvmExecute(script_context, self.blockchain_context, self.request_tx_context, self.reactor_state)
      # Quite overkill to deserialize entire CBOR, but we want to be sure a valid CBOR was returned
      loads(updated_reactor_state.state)
      loads(updated_reactor_state.ft_balances)
      loads(updated_reactor_state.nft_balances)
      if updated_reactor_state:
        self.request_tx_context.atomicals_spent_at_inputs = {}
        return DeployCommandResult(True, updated_reactor_state)
    except AtomicalConsensusExecutionError as ex:
      print(f'AtomicalConsensusExecutionError ex={ex}')
      return DeployCommandResult(False, None, ex)
    raise ValueError(f'Critical call error')
  
class AVMFactory:
  def __init__(self, logger, get_atomicals_id_mint_info, blockchain_context: RequestBlockchainContext, protocol_mint_data):
    self.logger = logger
    self.get_atomicals_id_mint_info = get_atomicals_id_mint_info
    self.blockchain_context = blockchain_context
    self.protocol_mint_data = protocol_mint_data
 
  def create_call_command(self, request_tx_context: RequestTxContext, atomicals_spent_at_inputs, reactor_state, reactor_atomical_mint_info):
    return CallCommand(self.logger, self.blockchain_context, request_tx_context, self.protocol_mint_data, atomicals_spent_at_inputs, reactor_state, reactor_atomical_mint_info)
  
  def create_deploy_command(self, request_tx_context: RequestTxContext, atomicals_spent_at_inputs, reactor_state):
    return DeployCommand(self.logger, self.blockchain_context, request_tx_context, self.protocol_mint_data, atomicals_spent_at_inputs, reactor_state)
    
  def create_token_incoming_structs(self, atomicals_spent_at_inputs):
    # Make a summary of tokens input
    nft_atomicals, ft_atomicals, _ = AtomicalsTransferBlueprintBuilder.build_atomical_input_summaries_by_type(self.get_atomicals_id_mint_info, atomicals_spent_at_inputs)
    nft_atomicals_avm_struct = {}
    ft_atomicals_avm_struct = {}
  
    for atomical_id, _ in nft_atomicals.items():
      # Todo: not sure if we need to reverse yet or not
      # atomical_id_reversed = bytearray(atomical_id)
      # atomical_id_reversed.reverse()
      nft_atomicals_avm_struct[atomical_id.hex()] = {
        "s": True
      }

    for atomical_id, input_summary in ft_atomicals.items():
      # Todo: not sure if we need to reverse yet or not
      # atomical_id_reversed = bytearray(atomical_id)
      # atomical_id_reversed.reverse()
      ft_atomicals_avm_struct[atomical_id.hex()] = {
        "total": input_summary.total_atomical_value
      }
    return nft_atomicals_avm_struct, ft_atomicals_avm_struct
