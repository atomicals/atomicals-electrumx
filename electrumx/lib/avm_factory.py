import bitcointx 
from electrumx.lib.atomicals_blueprint_builder import AtomicalsTransferBlueprintBuilder

class AVMFactory:
  '''Instantiate the wrapper and factory objects for handling AVM related requests'''
  def __init__(self, logger, atomicals_spent_at_inputs, operations_found_at_inputs):
    self.logger = logger
    self.atomicals_spent_at_inputs = atomicals_spent_at_inputs

  def get_modified_atomicals_spent_at_inputs(self):
    return self.atomicals_spent_at_inputs