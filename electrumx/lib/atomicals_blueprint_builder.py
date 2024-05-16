from electrumx.lib.util_atomicals import (
    is_splat_operation,
    is_split_operation,
    is_mint_operation,
    location_id_bytes_to_compact,
    is_op_return_subrealm_payment_marker_atomical_id,
    is_op_return_dmitem_payment_marker_atomical_id,
    compact_to_location_id_bytes,
    is_compact_atomical_id,
    is_integer_num,
    SUBNAME_MIN_PAYMENT_DUST_LIMIT
)
from electrumx.lib.hash import hash_to_hex_str, HASHX_LEN
from electrumx.lib.util import (
  unpack_le_uint64, unpack_le_uint16_from
)
from electrumx.lib.script import SCRIPTHASH_LEN, is_unspendable_legacy, is_unspendable_genesis

class FtColoringSummary:
  def __init__(self, atomical_id_to_expected_outs_map, fts_burned, cleanly_assigned, atomicals_list):
    self.atomical_id_to_expected_outs_map = atomical_id_to_expected_outs_map
    self.cleanly_assigned = cleanly_assigned
    self.fts_burned = fts_burned
    self.atomicals_list = atomicals_list
  
  def __repr__(self):
    return f'FtColoringSummary cleanly_assigned: {self.cleanly_assigned}, fts_burned: {self.fts_burned}, atomicals_list: {self.atomicals_list}'

class ExpectedOutputSet:
  '''Store the expected output indexes to be colored and the exponent for the outputs to apply'''
  def __init__(self, expected_outputs, expected_values):
      self.expected_outputs = expected_outputs
      self.expected_values = expected_values
    
  def __repr__(self):
     return f'ExpectedOutputSet expected_outputs: {self.expected_outputs}, expected_values: {self.expected_values}'

def build_reverse_output_to_atomical_id_exponent_map(atomical_id_to_output_index_map):
    if not atomical_id_to_output_index_map:
        return {}
    reverse_mapped = {}
    for atomical_id, output_info in atomical_id_to_output_index_map.items():
        for out_idx in output_info.expected_outputs:
            reverse_mapped[out_idx] = reverse_mapped.get(out_idx) or {}
            reverse_mapped[out_idx][atomical_id] = output_info.expected_values
    return reverse_mapped

def get_nominal_atomical_value(value):
    return value

def calculate_outputs_to_color_for_ft_atomical_ids(tx, ft_atomicals, sort_by_fifo, is_split_activated) -> FtColoringSummary:
    num_fts = len(ft_atomicals.keys())
    if num_fts == 0:
        return None
        # return FtColoringSummary(potential_atomical_ids_to_output_idxs_map, fts_burned, not non_clean_output_slots, atomical_list)
    atomical_list = order_ft_inputs(ft_atomicals, sort_by_fifo)
    next_start_out_idx = 0
    potential_atomical_ids_to_output_idxs_map = {}
    non_clean_output_slots = False
    utxo_cleanly_assigned = True
    fts_burned = {}
    for item in atomical_list:
      atomical_id = item.atomical_id
      # If a target exponent was provided, then use that instead
      cleanly_assigned, expected_outputs, remaining_value_from_assign = AtomicalsTransferBlueprintBuilder.assign_expected_outputs_basic(item.total_atomical_value, tx, next_start_out_idx, is_split_activated)
      if not cleanly_assigned:
        utxo_cleanly_assigned = False
      if not is_split_activated:
        if cleanly_assigned and len(expected_outputs) > 0:
          next_start_out_idx = expected_outputs[-1] + 1
          potential_atomical_ids_to_output_idxs_map[atomical_id] = ExpectedOutputSet(expected_outputs, item.total_atomical_value)
        else:
          # Erase the potential for safety
          potential_atomical_ids_to_output_idxs_map = {}
          non_clean_output_slots = True
          break
      else:
        if remaining_value_from_assign > 0:
          fts_burned[atomical_id] = remaining_value_from_assign
        # no need cleanly_assigned
        if len(expected_outputs) > 0:
          next_start_out_idx = expected_outputs[-1] + 1
          potential_atomical_ids_to_output_idxs_map[atomical_id] = ExpectedOutputSet(expected_outputs, item.total_atomical_value)
        else:
          # if no enable uxto
          potential_atomical_ids_to_output_idxs_map = {}
          non_clean_output_slots = True
          break

    # If the output slots did not fit cleanly, then default to just assigning everything from the 0'th output index
    if non_clean_output_slots:
      potential_atomical_ids_to_output_idxs_map = {}
      for item in atomical_list:
        atomical_id = item.atomical_id
        cleanly_assigned, expected_outputs, remaining_value_from_assign = AtomicalsTransferBlueprintBuilder.assign_expected_outputs_basic(item.total_atomical_value, tx, 0, is_split_activated)
        potential_atomical_ids_to_output_idxs_map[atomical_id] = ExpectedOutputSet(expected_outputs, item.total_atomical_value)
        if remaining_value_from_assign > 0:
          fts_burned[atomical_id] = remaining_value_from_assign
        if not cleanly_assigned:
          utxo_cleanly_assigned = False
      return FtColoringSummary(potential_atomical_ids_to_output_idxs_map, fts_burned, utxo_cleanly_assigned, atomical_list)
    return FtColoringSummary(potential_atomical_ids_to_output_idxs_map, fts_burned, utxo_cleanly_assigned, atomical_list)
  
class AtomicalsTransferBlueprintBuilderError(Exception):
    '''Raised when Atomicals Blueprint builder has an error'''


class AtomicalInputItem:
    """An input item struct"""

    def __init__(self, txin_index, sat_value: int, atomical_value: int):
        self.txin_index = txin_index
        self.sat_value = sat_value
        self.atomical_value = atomical_value


class AtomicalInputSummary:
    """Summarize a set of inputs for a transaction"""

    def __init__(self, atomical_id, atomical_type, mint_info):
        self.atomical_id = atomical_id
        self.type = atomical_type
        self.total_sat_value = 0
        self.total_atomical_value = 0
        self.input_indexes = []
        self.mint_info = mint_info

    def apply_input(self, tx_in_index, sat_value, atomical_value):
        self.total_sat_value += sat_value
        # Accumulate the total token value
        self.total_atomical_value += atomical_value
        # Track the current input index encountered and the details of the input such as
        # sat_value, token_value, exponent, txin index
        self.input_indexes.append(AtomicalInputItem(tx_in_index, sat_value, atomical_value))


class AtomicalColoredOutputFt:
    def __init__(self, sat_value: int, atomical_value: int, input_summary_info: AtomicalInputSummary):
        self.sat_value = sat_value
        self.atomical_value = atomical_value
        self.input_summary_info = input_summary_info

    def __repr__(self):
        return f'atomical colored output ft sat_value: {self.sat_value}, atomical_value: {self.atomical_value}'


class AtomicalColoredOutputNft:
  def __init__(self, input_summary_info: AtomicalInputSummary):
    self.input_summary_info = input_summary_info
    
class AtomicalFtOutputBlueprintAssignmentSummary:
  def __init__(self, outputs, fts_burned, cleanly_assigned, first_atomical_id):
    self.outputs = outputs 
    self.fts_burned = fts_burned
    self.cleanly_assigned = cleanly_assigned
    self.first_atomical_id = first_atomical_id
      
class AtomicalNftOutputBlueprintAssignmentSummary:
  def __init__(self, outputs):
    self.outputs = outputs 

def order_ft_inputs(ft_atomicals: AtomicalInputSummary, sort_by_fifo):
  atomical_list = []
  # If sorting is by FIFO, then get the mappng of which FTs are at which inputs
  if sort_by_fifo:
    input_idx_map = {}
    for atomical_id, ft_info in ft_atomicals.items():
      for input_index_for_atomical in ft_info.input_indexes:
        txin_index = input_index_for_atomical.txin_index
        input_idx_map[txin_index] = input_idx_map.get(txin_index) or []
        input_idx_map[txin_index].append(atomical_id)
    # Now for each input, we assign the atomicals, making sure to ignore the ones we've seen already
    seen_atomical_id_map = {}
    for input_idx, atomicals_array in sorted(input_idx_map.items()):
        for atomical_id in sorted(atomicals_array):
            if seen_atomical_id_map.get(atomical_id):       
                continue 
            seen_atomical_id_map[atomical_id] = True
            atomical_list.append(ft_atomicals[atomical_id])
  else:
      for atomical_id, ft_info in sorted(ft_atomicals.items()):
        atomical_list.append(ft_info)
  return atomical_list 
 
class AtomicalsTransferBlueprintBuilder:
  '''Atomicals transfer blueprint builder for calculating outputs to color'''
  def __init__(self, logger, atomicals_spent_at_inputs, operations_found_at_inputs, tx_hash, tx, get_atomicals_id_mint_info, sort_fifo, is_split_activated):
    self.logger = logger
    self.atomicals_spent_at_inputs = atomicals_spent_at_inputs
    self.operations_found_at_inputs = operations_found_at_inputs
    self.tx_hash = tx_hash
    self.tx = tx
    self.get_atomicals_id_mint_info = get_atomicals_id_mint_info
    self.sort_fifo = sort_fifo
    self.is_split_activated = is_split_activated
    nft_atomicals, ft_atomicals, atomical_ids_spent = AtomicalsTransferBlueprintBuilder.build_atomical_input_summaries_by_type(self.get_atomicals_id_mint_info, atomicals_spent_at_inputs)
    self.nft_atomicals = nft_atomicals
    self.ft_atomicals = ft_atomicals
    nft_output_blueprint, ft_output_blueprint = AtomicalsTransferBlueprintBuilder.calculate_output_blueprint(self.get_atomicals_id_mint_info, self.tx, self.nft_atomicals, self.ft_atomicals, self.atomicals_spent_at_inputs, self.operations_found_at_inputs, self.sort_fifo, self.is_split_activated)
    self.nft_output_blueprint = nft_output_blueprint
    self.ft_output_blueprint = ft_output_blueprint
    # if len(ft_atomicals) > 0 or len(nft_atomicals) > 0:
    #  self.logger.info(f'tx_hash={hash_to_hex_str(tx_hash)} atomicals_spent_at_inputs={encode_atomical_ids_hex(atomicals_spent_at_inputs)} operations_found_at_inputs={operations_found_at_inputs}')
    self.fts_burned = ft_output_blueprint.fts_burned
    self.cleanly_assigned = ft_output_blueprint.cleanly_assigned
    self.are_fts_burned = len(ft_output_blueprint.fts_burned) > 0
    self.atomical_ids_spent = atomical_ids_spent
    self.is_mint = is_mint_operation(self.operations_found_at_inputs)

  @classmethod
  def order_ft_inputs(cls, ft_atomicals, sort_by_fifo):
    ''' Order the inputs by FIFO or by legacy '''
    atomical_list = []
    # If sorting is by FIFO, then get the mappng of which FTs are at which inputs
    if sort_by_fifo:
      input_idx_map = {}
      for atomical_id, ft_info in ft_atomicals.items():
          for input_index_for_atomical in ft_info.input_indexes:
            txin_index = input_index_for_atomical.txin_index
            input_idx_map[txin_index] = input_idx_map.get(txin_index) or []
            input_idx_map[txin_index].append({
                'atomical_id': atomical_id,
            })
      # Now for each input, we assign the atomicals, making sure to ignore the ones we've seen already
      seen_atomical_id_map = {}
      for input_idx, atomicals_array in sorted(input_idx_map.items()):
        for atomical_id_info in sorted(atomicals_array):
          if seen_atomical_id_map.get(atomical_id_info['atomical_id']):       
            continue 
          seen_atomical_id_map[atomical_id_info['atomical_id']] = True
          atomical_list.append(ft_atomicals[atomical_id_info['atomical_id']])
    else:
      for atomical_id, ft_info in sorted(ft_atomicals.items()):
        atomical_list.append(ft_info)
    return atomical_list

  # Maps all the inputs that contain NFTs
  @classmethod
  def build_nft_input_idx_to_atomical_map(cls, get_atomicals_id_mint_info, atomicals_spent_at_inputs):
    input_idx_to_atomical_ids_map = {}
    for txin_index, atomicals_entry_list in atomicals_spent_at_inputs.items():
      for atomicals_entry in atomicals_entry_list:
        atomical_id = atomicals_entry['atomical_id']
        atomical_mint_info = get_atomicals_id_mint_info(atomical_id, True)
        if not atomical_mint_info: 
            raise AtomicalsTransferBlueprintBuilderError(f'build_nft_input_idx_to_atomical_map {atomical_id.hex()} not found in mint info. IndexError.')
        if atomical_mint_info['type'] != 'NFT':
            continue
        input_idx_to_atomical_ids_map[txin_index] = input_idx_to_atomical_ids_map.get(txin_index) or {}
        input_idx_to_atomical_ids_map[txin_index][atomical_id] = AtomicalInputSummary(atomical_id, atomical_mint_info['type'], atomical_mint_info)
        # Populate the summary information
        value = atomicals_entry['data_value']['sat_value']
        # Exponent is always 0 for NFTs
        input_idx_to_atomical_ids_map[txin_index][atomical_id].apply_input(txin_index, value, value)
    return input_idx_to_atomical_ids_map

  @classmethod
  def calculate_nft_atomicals_regular(cls, nft_map, nft_atomicals, tx, operations_found_at_inputs, sort_fifo):
    # Use a simplified mapping of NFTs using FIFO to the outputs 
    if sort_fifo:
      next_output_idx = 0
      map_output_idxs_for_atomicals = {}
      # Build a map of input ids to NFTs
      for input_idx, atomicals_ids_map in nft_map.items():
        found_atomical_at_input = False
        for atomical_id, atomical_summary_info in atomicals_ids_map.items():
          found_atomical_at_input = True 
          expected_output_index = next_output_idx
          if expected_output_index >= len(tx.outputs) or is_unspendable_genesis(tx.outputs[expected_output_index].pk_script) or is_unspendable_legacy(tx.outputs[expected_output_index].pk_script):
            expected_output_index = 0
          # Also keep them at the 0'th index if the split command was used
          if is_split_operation(operations_found_at_inputs):
            expected_output_index = 0    
          map_output_idxs_for_atomicals[expected_output_index] = map_output_idxs_for_atomicals.get(expected_output_index) or {'atomicals': {}}
          map_output_idxs_for_atomicals[expected_output_index]['atomicals'][atomical_id] = atomical_summary_info
        if found_atomical_at_input:
          next_output_idx += 1
      return AtomicalNftOutputBlueprintAssignmentSummary(map_output_idxs_for_atomicals)
    else:
      map_output_idxs_for_atomicals = {}
      # Assign NFTs the legacy way with 1:1 inputs to outputs
      for atomical_id, atomical_summary_info in nft_atomicals.items():
        expected_output_index = AtomicalsTransferBlueprintBuilder.calculate_nft_output_index_legacy(atomical_summary_info.input_indexes[0].txin_index, tx, operations_found_at_inputs)
        map_output_idxs_for_atomicals[expected_output_index] = map_output_idxs_for_atomicals.get(expected_output_index) or {'atomicals': {}}
        map_output_idxs_for_atomicals[expected_output_index]['atomicals'][atomical_id] = atomical_summary_info
      return AtomicalNftOutputBlueprintAssignmentSummary(map_output_idxs_for_atomicals)
    
  @classmethod
  def calculate_nft_atomicals_splat(cls, nft_atomicals, tx):
      # Splat takes all of the NFT atomicals across all inputs (including multiple atomicals at the same utxo) 
      # and then separates them into their own distinctive output such that the result of the operation is no two atomicals
      # will share a resulting output. This operation requires that there are at least as many outputs as there are NFT atomicals
      # If there are not enough, then this is considered a noop and those extra NFTs are assigned to output 0
      # If there are enough outputs, then the earliest atomical (sorted lexicographically in ascending order) goes to the 0'th output,
      # then the second atomical goes to the 1'st output, etc until all atomicals are assigned to their own output.
      expected_output_index_incrementing = 0 # Begin assigning splatted atomicals at the 0'th index
      output_colored_map = {}
      for atomical_id, atomical_summary_info in sorted(nft_atomicals.items()):
          expected_output_index = expected_output_index_incrementing
          if expected_output_index_incrementing >= len(tx.outputs) or is_unspendable_genesis(tx.outputs[expected_output_index_incrementing].pk_script) or is_unspendable_legacy(tx.outputs[expected_output_index_incrementing].pk_script):
              expected_output_index = 0
          output_colored_map[expected_output_index] = output_colored_map.get(expected_output_index) or {'atomicals': {}}
          output_colored_map[expected_output_index]['atomicals'][atomical_id] = atomical_summary_info
          expected_output_index_incrementing += 1 
      return AtomicalNftOutputBlueprintAssignmentSummary(output_colored_map) 
      
  @classmethod
  def calculate_output_blueprint_nfts(cls, get_atomicals_id_mint_info, tx, nft_atomicals, atomicals_spent_at_inputs, operations_found_at_inputs, sort_fifo):
      if not nft_atomicals or len(nft_atomicals) == 0:
          return AtomicalNftOutputBlueprintAssignmentSummary({})
      should_splat_nft_atomicals = is_splat_operation(operations_found_at_inputs)
      if should_splat_nft_atomicals and len(nft_atomicals.keys()) > 0:
          return AtomicalsTransferBlueprintBuilder.calculate_nft_atomicals_splat(nft_atomicals, tx)
      else:
        # To sort by fifo for NFTs, we also need to calculate a mapping of the nfts to inputs first
        nft_map = AtomicalsTransferBlueprintBuilder.build_nft_input_idx_to_atomical_map(get_atomicals_id_mint_info, atomicals_spent_at_inputs)
        return AtomicalsTransferBlueprintBuilder.calculate_nft_atomicals_regular(nft_map, nft_atomicals, tx, operations_found_at_inputs, sort_fifo)  
  
  @classmethod
  def calculate_output_blueprint_fts(cls, tx, ft_atomicals, operations_found_at_inputs, sort_fifo, is_split_activated):
      if not ft_atomicals or len(ft_atomicals) == 0:
          return AtomicalFtOutputBlueprintAssignmentSummary({}, {}, True, None) 
      
      # Split apart multiple NFT/FT from a UTXO
      should_split_ft_atomicals = is_split_operation(operations_found_at_inputs)
      if should_split_ft_atomicals:
          return AtomicalsTransferBlueprintBuilder.color_ft_atomicals_split(ft_atomicals, operations_found_at_inputs, tx, is_split_activated)
      # Normal assignment in all cases including fall through of failure to provide a target exponent in the above resubstantiation
      return AtomicalsTransferBlueprintBuilder.color_ft_atomicals_regular(ft_atomicals, tx, sort_fifo, is_split_activated)

  @classmethod
  def color_ft_atomicals_split(cls, ft_atomicals, operations_found_at_inputs, tx, is_split_activated):
    output_colored_map = {}
    fts_burned = {}
    cleanly_assigned = True
    for atomical_id, atomical_info in sorted(ft_atomicals.items()):
      expected_output_indexes = []
      remaining_value = atomical_info.total_atomical_value
      # The FT type has the 'split' (y) method which allows us to selectively split (skip) a certain total number of token units (satoshis)
      # before beginning to color the outputs.
      # Essentially this makes it possible to "split" out multiple FT's located at the same input
      # If the input at index 0 has the split operation, then it will apply for the atomical token generally across all inputs and the first output will be skipped
      total_amount_to_skip = 0
      # Uses the compact form of atomical id as the keys for developer convenience
      total_amount_to_skip_potential = operations_found_at_inputs and operations_found_at_inputs.get('payload').get(location_id_bytes_to_compact(atomical_id))
      # Sanity check to ensure it is a non-negative integer
      if isinstance(total_amount_to_skip_potential, int) and total_amount_to_skip_potential >= 0:
        total_amount_to_skip = total_amount_to_skip_potential
      total_skipped_so_far = 0
      if is_split_activated:
        for out_idx, txout in enumerate(tx.outputs):
          # If the first output should be skipped and we have not yet done so, then skip/ignore it
          if total_amount_to_skip > 0 and total_skipped_so_far < total_amount_to_skip:
              total_skipped_so_far += txout.value
              continue
          expected_output_indexes.append(out_idx)
          if txout.value <= remaining_value:
            expected_value = txout.value
          else:
            expected_value = remaining_value
          remaining_value -= txout.value
          output_colored_map[out_idx] = output_colored_map.get(out_idx) or {'atomicals': {}}
          output_colored_map[out_idx]['atomicals'][atomical_id] = AtomicalColoredOutputFt(txout.value, expected_value, atomical_info)
          if remaining_value == 0:
              break
          if remaining_value < 0:
              remaining_value = 0
              cleanly_assigned = False # Used to indicate that all was cleanly assigned
              break
        if remaining_value != 0:
          cleanly_assigned = False
          fts_burned[atomical_id] = remaining_value
      else:
        # is_split_activated logic
        # use if else keep it simple
        for out_idx, txout in enumerate(tx.outputs):
          if total_amount_to_skip > 0 and total_skipped_so_far < total_amount_to_skip:
            total_skipped_so_far += txout.value
            continue
          # For all remaining outputs attach colors as long as there is adequate remaining_value left to cover the entire output value
          if txout.value <= remaining_value:
            expected_output_indexes.append(out_idx)
            remaining_value -= txout.value
            output_colored_map[out_idx] = output_colored_map.get(out_idx) or {'atomicals': {}}
            output_colored_map[out_idx]['atomicals'][atomical_id] = AtomicalColoredOutputFt(txout.value, txout.value, atomical_info)
            # We are done assigning all remaining values
            if remaining_value == 0:
                break
          # Exit case when we have no more remaining_value to assign or the next output is greater than what we have in remaining_value
          if txout.value > remaining_value or remaining_value < 0:
              cleanly_assigned = False # Used to indicate that all was cleanly assigned
              fts_burned[atomical_id] = remaining_value
              break
        if remaining_value != 0:
          cleanly_assigned = False
          fts_burned[atomical_id] = remaining_value
    return AtomicalFtOutputBlueprintAssignmentSummary(output_colored_map, fts_burned, cleanly_assigned, None)

  @classmethod
  def color_ft_atomicals_regular(cls, ft_atomicals, tx, sort_fifo, is_split_activated):
      output_colored_map = {}
      ft_coloring_summary = calculate_outputs_to_color_for_ft_atomical_ids(tx, ft_atomicals, sort_fifo, is_split_activated)
      if not ft_coloring_summary: 
        return AtomicalFtOutputBlueprintAssignmentSummary({}, {}, True, None) 
      
      first_atomical_id = None 
      if ft_coloring_summary.atomicals_list and len(ft_coloring_summary.atomicals_list):
        first_atomical_id = ft_coloring_summary.atomicals_list[0].atomical_id
      
      if not is_split_activated:
        for atomical_id, atomical_info in ft_coloring_summary.atomical_id_to_expected_outs_map.items():
          for expected_output_index in atomical_info.expected_outputs:
              txout = tx.outputs[expected_output_index]
              output_colored_map[expected_output_index] = output_colored_map.get(expected_output_index) or {'atomicals': {}}
              output_colored_map[expected_output_index]['atomicals'][atomical_id] = AtomicalColoredOutputFt(txout.value, txout.value, atomical_info)
        return AtomicalFtOutputBlueprintAssignmentSummary(output_colored_map, ft_coloring_summary.fts_burned, ft_coloring_summary.cleanly_assigned, first_atomical_id)
      else:
        # for multiple expected_outputs case
        cleanly_assigned = True
        for atomical_id, atomical_info in ft_coloring_summary.atomical_id_to_expected_outs_map.items():
          total_value = atomical_info.expected_values
          if not ft_coloring_summary.cleanly_assigned:
             cleanly_assigned = False
          for expected_output_index in atomical_info.expected_outputs:
              txout = tx.outputs[expected_output_index]
              output_colored_map[expected_output_index] = output_colored_map.get(expected_output_index) or {'atomicals': {}}
              if total_value >= txout.value:
                 expected_value = txout.value
                 total_value -= expected_value
              else:
                 expected_value = total_value
              output_colored_map[expected_output_index]['atomicals'][atomical_id] = AtomicalColoredOutputFt(txout.value, expected_value, atomical_info)
        return AtomicalFtOutputBlueprintAssignmentSummary(output_colored_map, ft_coloring_summary.fts_burned, cleanly_assigned, first_atomical_id)

  @classmethod
  def calculate_output_blueprint(cls, get_atomicals_id_mint_info, tx, nft_atomicals, ft_atomicals, atomicals_spent_at_inputs, operations_found_at_inputs, sort_fifo, is_split_activated):
      nft_blueprint = AtomicalsTransferBlueprintBuilder.calculate_output_blueprint_nfts(get_atomicals_id_mint_info, tx, nft_atomicals, atomicals_spent_at_inputs, operations_found_at_inputs, sort_fifo)
      ft_blueprint = AtomicalsTransferBlueprintBuilder.calculate_output_blueprint_fts(tx, ft_atomicals, operations_found_at_inputs, sort_fifo, is_split_activated)
      return nft_blueprint, ft_blueprint 

  # Builds a map and image of all the inputs and their sat_value and atomical_value (adjusted by exponent)
  # This is the base datastructure used to color FT outputs and determine what exact sat_value will be needed to maintain input token value to outputs
  @classmethod
  def build_atomical_input_summaries(cls, get_atomicals_id_mint_info, map_atomical_ids_to_summaries, atomicals_entry_list, txin_index):
      atomicals_id_mint_info_map = {}
      # For each input atomical spent at the current input...
      for atomicals_entry in atomicals_entry_list:
          atomical_id = atomicals_entry['atomical_id']
          # value, = unpack_le_uint64(atomicals_entry['data'][HASHX_LEN + SCRIPTHASH_LEN : HASHX_LEN + SCRIPTHASH_LEN + 8])
          # exponent, = unpack_le_uint16_from(atomicals_entry['data'][HASHX_LEN + SCRIPTHASH_LEN + 8: HASHX_LEN + SCRIPTHASH_LEN + 8 + 2])
          sat_value = atomicals_entry['data_value']['sat_value']
          atomical_value = atomicals_entry['data_value']['atomical_value']
          # Perform a cache lookup for the mint information since we do not want to query multiple times for same input atomical_id
          if not atomicals_id_mint_info_map.get(atomical_id):
              atomical_mint_info = get_atomicals_id_mint_info(atomical_id, True)
              if not atomical_mint_info: 
                  raise AtomicalsTransferBlueprintBuilderError(f'build_atomical_input_summaries {atomical_id.hex()} not found in mint info. IndexError.')
              atomicals_id_mint_info_map[atomical_id] = atomical_mint_info
          # The first time we encounter the atomical we build the initialization struct
          # it doesn't matter if it's an NFT or FT
          # However note that only FTs will have an exponent >= 0 as NFT will always be exponent = 0
          if not map_atomical_ids_to_summaries.get(atomical_id):
            map_atomical_ids_to_summaries[atomical_id] = AtomicalInputSummary(atomical_id, atomicals_id_mint_info_map[atomical_id]['type'], atomicals_id_mint_info_map[atomical_id])
          # use atomical_value, not value
          # for Partially case
          map_atomical_ids_to_summaries[atomical_id].apply_input(txin_index, sat_value, atomical_value)
      return map_atomical_ids_to_summaries
  
  @classmethod
  def build_atomical_input_summaries_by_type(cls, get_atomicals_id_mint_info, atomicals_spent_at_inputs):
      map_atomical_ids_to_summaries = {}
      for txin_index, atomicals_entry_list in atomicals_spent_at_inputs.items():
          # Accumulate the total input value by atomical_id
          # The value will be used below to determine the amount of input we can allocate for FT's
          AtomicalsTransferBlueprintBuilder.build_atomical_input_summaries(get_atomicals_id_mint_info, map_atomical_ids_to_summaries, atomicals_entry_list, txin_index)
      # Group the atomicals by NFT and FT for easier handling
      nft_atomicals = {}
      ft_atomicals = {}
      for atomical_id, mint_info in map_atomical_ids_to_summaries.items(): 
          if mint_info.type == 'NFT':
              nft_atomicals[atomical_id] = mint_info
          elif mint_info.type == 'FT':
              ft_atomicals[atomical_id] = mint_info
          else:
              raise AtomicalsTransferBlueprintBuilderError(f'color_atomicals_outputs: Invalid type. IndexError')
      atomicals_ids_spent = []
      for atomical_id, unused in nft_atomicals.items():
        atomicals_ids_spent.append(atomical_id)
      for atomical_id, unused in ft_atomicals.items():
        atomicals_ids_spent.append(atomical_id)
      return nft_atomicals, ft_atomicals, atomicals_ids_spent

  @classmethod
  def calculate_nft_output_index_legacy(cls, input_idx, tx, operations_found_at_inputs):
    expected_output_index = input_idx
    # If it was unspendable output, then just set it to the 0th location
    # ...and never allow an NFT atomical to be burned accidentally by having insufficient number of outputs either
    # The expected output index will become the 0'th index if the 'x' extract operation was specified or there are insufficient outputs
    if expected_output_index >= len(tx.outputs) or is_unspendable_genesis(tx.outputs[expected_output_index].pk_script) or is_unspendable_legacy(tx.outputs[expected_output_index].pk_script):
        expected_output_index = 0
    # If this was the 'split' (y) command, then also move them to the 0th output
    if is_split_operation(operations_found_at_inputs):
      expected_output_index = 0    
    return expected_output_index

  # Assign the ft quantity basic from the start_out_idx to the end until exhausted
  # Returns the sequence of output indexes that matches until the final one that matched
  # Also returns whether it fit cleanly in (ie: exact with no left overs or under)
  @classmethod
  def assign_expected_outputs_basic(cls, total_value_to_assign, tx, start_out_idx, is_split_activated):
      expected_output_indexes = []
      remaining_value = total_value_to_assign
      idx_count = 0
      if start_out_idx >= len(tx.outputs):
          return False, expected_output_indexes, 0
      for out_idx, txout in enumerate(tx.outputs): 
          # Only consider outputs from the starting index
          if idx_count < start_out_idx:
              idx_count += 1
              continue
          # For all remaining outputs attach colors as long as there is adequate remaining_value left to cover the entire output value
          if is_unspendable_genesis(txout.pk_script) or is_unspendable_legacy(txout.pk_script):
              idx_count += 1
              continue
          if is_split_activated:
              # Add out_idx
              expected_output_indexes.append(out_idx)
              remaining_value -= txout.value
              if remaining_value > 0:
                continue
              if remaining_value == 0:
                  return True, expected_output_indexes, remaining_value
              return False, expected_output_indexes, remaining_value
          else:
            if txout.value <= remaining_value:
                expected_output_indexes.append(out_idx)
                remaining_value -= txout.value
                if remaining_value == 0:
                    # The token input was fully exhausted cleanly into the outputs
                    return True, expected_output_indexes, remaining_value
            # Exit case output is greater than what we have in remaining_value
            else:
                # There was still some token units left, but the next output was greater than the amount. Therefore we burned the remainder tokens.
                return False, expected_output_indexes, remaining_value
          idx_count += 1
      # There was still some token units left, but there were no more outputs to take the quantity. Tokens were burned.
      return False, expected_output_indexes, remaining_value

  @classmethod
  def get_atomical_id_for_payment_marker_if_found(cls, tx):
    ''' Get the atomical id if found for a payment marker op_return'''
    found_atomical_id = None
    for idx, txout in enumerate(tx.outputs):
        # Note that we accept 'p' and 'd' as payment marker types for either dmitem or subrealm payments now
        found_atomical_id = is_op_return_subrealm_payment_marker_atomical_id(txout.pk_script)
        if found_atomical_id:
          return found_atomical_id, idx, 'subrealm'
        found_atomical_id = is_op_return_dmitem_payment_marker_atomical_id(txout.pk_script)
        if found_atomical_id:
          return found_atomical_id, idx, 'dmitem'
        
    return found_atomical_id, None, None
  
  def are_payments_satisfied(self, expected_payment_outputs):
    if not isinstance(expected_payment_outputs, dict) or len(expected_payment_outputs.keys()) < 1:
      return False
    
    # Just in case do not allow payments to be satisfied for split operation as it allows reassigning ARC20
    if self.is_split_operation():
      return False 
    
    # Just in case also ensure there was a payment marker for the current tx
    atomical_id_to_pay, marker_idx, entity_type = AtomicalsTransferBlueprintBuilder.get_atomical_id_for_payment_marker_if_found(self.tx)
    if not atomical_id_to_pay:
      return False 
    
    expected_output_keys_satisfied = {}
    # Set up the expected output scripts to be satisfied for the payments
    for output_script_key, output_script_details in expected_payment_outputs.items():
      ft_atomical_id = output_script_details.get('id')
      if ft_atomical_id:
        if not is_compact_atomical_id(ft_atomical_id):
          return False
        # Map the output script hex with the atomical id that it must be colored with
        atomical_id_expected_color_long_from = compact_to_location_id_bytes(ft_atomical_id)
        expected_output_keys_satisfied[output_script_key + atomical_id_expected_color_long_from.hex()] = False
      else:
        # Map the output script hex only
        expected_output_keys_satisfied[output_script_key] = False

    # Prepare the mapping of which ARC20 is paid at which output
    ft_coloring_summary = calculate_outputs_to_color_for_ft_atomical_ids(self.tx, self.ft_atomicals, self.sort_fifo, self.is_split_activated)
    output_idx_to_atomical_id_map = {}
    if ft_coloring_summary:
      output_idx_to_atomical_id_map = build_reverse_output_to_atomical_id_exponent_map(ft_coloring_summary.atomical_id_to_expected_outs_map)
    
    # For each of the outputs, assess whether it matches any of the required payment output expectations
    for idx, txout in enumerate(self.tx.outputs):
      output_script_hex = txout.pk_script.hex()
      # Ensure there is a payment rule for the current output of the tx, or skip it
      expected_output_payment_value_dict = expected_payment_outputs.get(output_script_hex, None)
      if not expected_output_payment_value_dict or not isinstance(expected_output_payment_value_dict, dict):
          continue
      
      # There is no value defined or the expected payment is below the dust limit, or skip it
      expected_output_payment_value = expected_output_payment_value_dict.get('v', None)
      if not is_integer_num(expected_output_payment_value) or expected_output_payment_value < SUBNAME_MIN_PAYMENT_DUST_LIMIT:
        continue 
      
      expected_output_payment_id_type = expected_output_payment_value_dict.get('id', None)
      # If it's a regular satoshi payment, then just check it is at least the amount of the expected payment value
      if not expected_output_payment_id_type:
          # Normal satoshi payment just check the amount of the sats is the expected amount
          if txout.value >= expected_output_payment_value:
            expected_output_keys_satisfied[output_script_hex] = True # Mark that the output was matched at least once   
      else:
        # Otherwise it is a payment in a specific ARC20 fungible token
        expected_output_payment_id_type_long_form = compact_to_location_id_bytes(expected_output_payment_id_type)
        # Check in the reverse map if the current output idx is colored with the expected color
        output_summary = output_idx_to_atomical_id_map.get(idx)
        if output_summary and output_summary.get(expected_output_payment_id_type_long_form, None) != None:
          # Ensure the normalized atomical_value is greater than or equal to the expected payment amount in that token type
          # exponent_for_for_atomical_id = output_summary.get(expected_output_payment_id_type_long_form)
          atomical_value = get_nominal_atomical_value(txout.value)
          if atomical_value >= expected_output_payment_value:
            expected_output_keys_satisfied[output_script_hex + expected_output_payment_id_type_long_form.hex()] = True # Mark that the output was matched at least once
    # Check if there are any unsatisfied requirements
    for output_script_not_used, satisfied in expected_output_keys_satisfied.items():
        if not satisfied:
          self.logger.warning(f'are_payments_satisfied is_all_outputs_matched_not_satisfied={expected_output_keys_satisfied} tx_hash={hash_to_hex_str(self.tx_hash)}')
          return False
    # We got this far that means all requirements were satisfied, do one final check to ensure there was at least one payment output required                
    return len(expected_output_keys_satisfied) > 0 
  
  def validate_ft_transfer_has_no_inflation(self, atomical_id_to_expected_outs_map, tx, ft_atomicals):
    sanity_check_sums = {}
    
    for atomical_id, outputs_to_color in atomical_id_to_expected_outs_map.items():
        sanity_check_sums[atomical_id] = 0
        for expected_output_index in outputs_to_color:
            sanity_check_sums[atomical_id] += tx.outputs[expected_output_index].value
    
    # Sanity check that there can be no inflation
    for atomical_id, ft_info in sorted(ft_atomicals.items()):
        sum_out_value = sanity_check_sums.get(atomical_id)
        input_value = ft_info['atomical_value']
        if sum_out_value and sum_out_value > input_value:
            atomical_id_compact = location_id_bytes_to_compact(atomical_id)
            raise AtomicalsTransferBlueprintBuilderError(f'validate_ft_transfer_has_no_inflation: Fatal error the output sum of outputs is greater than input sum for Atomical: atomical_id={atomical_id_compact} input_value={input_value} sum_out_value={sum_out_value} ft_atomicals={ft_atomicals}')
  
  def is_split_operation(self):
    return is_split_operation(self.operations_found_at_inputs)
    
  def get_nft_output_blueprint(self):
    return self.nft_output_blueprint
  
  def get_ft_output_blueprint(self):
    return self.ft_output_blueprint

  def get_are_fts_burned(self):
    return self.are_fts_burned

  def get_fts_burned(self):
    return self.fts_burned
  
  def get_atomical_ids_spent(self):
    return self.atomical_ids_spent
