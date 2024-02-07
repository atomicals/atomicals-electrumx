import bitcointx 
from electrumx.lib.atomicals_blueprint_builder import AtomicalsTransferBlueprintBuilder

class AVMFactory:
  '''Instantiate the wrapper and factory objects for handling AVM related requests'''
  def __init__(self, logger, atomicals_spent_at_inputs, operations_found_at_inputs, tx_hash, tx, get_atomicals_id_mint_info):
    self.logger = logger
    self.blueprint_builder = AtomicalsTransferBlueprintBuilder(self.logger, atomicals_spent_at_inputs, operations_found_at_inputs, tx_hash, tx, get_atomicals_id_mint_info, True)
    # Todo: pass in network
    with bitcointx.ChainParams('bitcoin/livenet') as params:
      self.logger.info(f"{params.readable_name} params ({params.name}) are in effect")

  def evaluate(self):
    return False